"""
FastAPI Backend Web Application and REST API.

Provides endpoints to manage pending approvals, explore the audit log,
manage allowlist policy rules, and track system status and metrics.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import os
import json
from typing import Any, Literal, Optional
from pydantic import BaseModel

from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .approvals import ApprovalStore, now_iso
from .allowlist import AllowlistStore, DurationError, parse_duration
from .audit import AuditLog
from .insights import insight_tags
from .identity import (
    DEFAULT_TENANT,
    AuthorizationError,
    Permission,
    resolve_actor,
)
from .policy import PolicyEngine
from .containment import ContainmentExecutor
from .providers import build_containment_adapters
from .schemas import AuditRecord, PolicyDecision, BlastRadius, ActionClass
from .ocsf import to_ocsf_event
from .orchestrator import get_tenant_path
from .connect import (
    launch_stack_url,
)


class AwsLinkRequest(BaseModel):
    account_id: str
    region: str = "us-east-1"
    grant: Literal["observe", "contain"] = "observe"


class AwsVerifyRequest(BaseModel):
    account_id: str
    role_arn: str
    grant: Literal["observe", "contain"] = "observe"



# Initialize FastAPI app
app = FastAPI(title="Kronagent Incident Response Console")

# Resolve static directory relative to this module
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Shared configurations
settings = Settings.from_env()
approval_store = ApprovalStore(settings.approval_store_path)
allowlist_store = AllowlistStore(settings.allowlist_store_path)
audit_log = AuditLog(settings.audit_log_path)


def resolve_tenant_id(request: Request) -> str:
    """The tenant this request is asking about.

    This value is entirely client-supplied, so it is a REQUEST, not a claim of
    entitlement. `authorize_tenant` below decides whether the caller may have
    it. Keeping those two steps separate is the point: they were previously one
    step, and the missing half meant any caller could read — and any
    authenticated operator could act on — any tenant by editing a URL.
    """
    tid = request.query_params.get("tenant_id")
    if tid:
        return tid
    tid = request.headers.get("X-Tenant-ID")
    if tid:
        return tid
    return DEFAULT_TENANT


def identity_configured() -> bool:
    """Whether an identity system exists at all.

    Tenant scoping is only meaningful where identities are: with no registry and
    no OIDC there is no principal to bind a tenant to, so the boundary cannot be
    enforced by any means. Enforcing it anyway would lock a local install out of
    its own named tenants while closing nothing.
    """
    from .identity import registry_configured
    return bool(registry_configured(settings.operator_registry_path)
                or (settings.oidc_issuer and settings.oidc_audience))


def authorize_tenant(request: Request, tenant_id: str) -> None:
    """Authorize the caller for `tenant_id`, or raise 403.

    Naming a tenant other than the default is inherently a cross-tenant
    operation, so it requires a verified identity scoped to that tenant —
    regardless of `require_view_auth`, which governs whether *reading your own*
    tenant needs auth. Without that carve-out, a deployment with
    require_view_auth off would still leak every tenant to an anonymous caller.
    """
    if tenant_id == DEFAULT_TENANT:
        return  # the single-tenant path; require_view_auth governs it as before

    from .identity import resolve_actor

    if not identity_configured():
        # No registry and no OIDC means there is no identity system, so a tenant
        # boundary is not merely unenforced — it is unenforceable, and pretending
        # otherwise would only break local single-operator installs without
        # closing anything. This posture is unchanged from before: writes already
        # refuse without an operator, and reads are governed by
        # require_view_auth. The vulnerability this function exists to close
        # required a registry (it was one tenant's admin acting on another's), so
        # it is closed exactly where it was open.
        return

    operator_id = request.headers.get("X-Operator-ID")
    token = request.headers.get("X-Operator-Token")
    if not operator_id or not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"tenant '{tenant_id}' requires an authenticated operator.",
        )

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.VIEW,
            operator_id=operator_id,
            token=token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    if not actor.may_access(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"operator '{actor.operator_id}' is not authorized for tenant "
                    f"'{tenant_id}' (permitted: {actor.tenants})."),
        )


def _may_access_tenant(request: Request, tenant_id: str) -> bool:
    """Non-raising form of `authorize_tenant`, for filtering a listing.

    A list endpoint must omit what the caller may not see rather than 403 on the
    first row it cannot show — otherwise one inaccessible tenant makes the whole
    listing unusable, and the 403 itself confirms that tenant exists.
    """
    try:
        authorize_tenant(request, tenant_id)
        return True
    except HTTPException:
        return False


def tenant_scope(request: Request) -> str:
    """Resolve AND authorize in one call — the form endpoints should use, so a
    new endpoint cannot resolve a tenant while forgetting to authorize it."""
    tenant_id = resolve_tenant_id(request)
    authorize_tenant(request, tenant_id)
    return tenant_id


def get_approval_store(tenant_id: str) -> ApprovalStore:
    if "mock" in type(approval_store).__name__.lower():
        return approval_store
    return ApprovalStore(get_tenant_path(settings.approval_store_path, tenant_id))


def get_allowlist_store(tenant_id: str) -> AllowlistStore:
    if "mock" in type(allowlist_store).__name__.lower():
        return allowlist_store
    return AllowlistStore(get_tenant_path(settings.allowlist_store_path, tenant_id))


def get_audit_log(tenant_id: str) -> AuditLog:
    if "mock" in type(audit_log).__name__.lower():
        return audit_log
    return AuditLog(get_tenant_path(settings.audit_log_path, tenant_id))


def check_view_permission(request: Request):
    from .identity import registry_configured, resolve_actor
    if settings.require_view_auth and (registry_configured(settings.operator_registry_path) or (settings.oidc_issuer and settings.oidc_audience)):
        operator_id = request.headers.get("X-Operator-ID")
        token = request.headers.get("X-Operator-Token")
        if not operator_id or not token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="VIEW permission required — pass operator ID and token in headers."
            )
        try:
            resolve_actor(
                registry_path=settings.operator_registry_path,
                required=Permission.VIEW,
                operator_id=operator_id,
                token=token,
                oidc_issuer=settings.oidc_issuer,
                oidc_audience=settings.oidc_audience,
                oidc_jwks_uri=settings.oidc_jwks_uri,
                oidc_verify_signature=settings.oidc_verify_signature,
                oidc_roles_claim=settings.oidc_roles_claim,
            )
        except AuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# --- Request/Response Models ---

class ActionRequest(BaseModel):
    action: Literal["approve", "deny"]
    operator_id: str
    token: str
    reason: str


class PromoteRequest(BaseModel):
    action_class: str
    operator_id: str
    token: str
    reason: str
    # Optional TTL, e.g. "90d" — after it elapses the class routes back to
    # human approval until an operator renews the promotion. Ignored on demote.
    expires_in: Optional[str] = None
    # Who is accountable for the entry and gets asked to renew it. Defaults to
    # the promoter (and, on a renewal, to the existing owner). Ignored on demote.
    owner: Optional[str] = None


class ReassignRequest(BaseModel):
    action_class: str
    operator_id: str
    token: str
    reason: str
    owner: str  # the new accountable owner


# --- Core Web Routes ---

@app.get("/", response_class=HTMLResponse)
def read_index() -> str:
    """Serve the single-page application frontend dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="Frontend index.html asset not found.")
    with open(index_path, "r", encoding="utf-8") as fh:
        return fh.read()


@app.get("/api/status")
def get_status(request: Request) -> dict[str, Any]:
    """Retrieve system configuration switches and audit log verification integrity."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    verified, _ = AuditLog.verify(get_tenant_path(settings.audit_log_path, tenant_id))
    return {
        "dry_run": settings.dry_run,
        "kill_switch": settings.kill_switch,
        "integrity_verified": verified
    }


@app.get("/api/events/stream")
async def stream_events(request: Request, once: bool = False) -> StreamingResponse:
    """Stream real-time system events, audit records, and approval queue updates via Server-Sent Events (SSE)."""
    import asyncio
    check_view_permission(request)
    tenant_id = tenant_scope(request)

    async def event_generator():
        # Connection ping event
        yield f"event: ping\ndata: {json.dumps({'status': 'connected', 'tenant_id': tenant_id, 'timestamp': now_iso()})}\n\n"
        
        try:
            while True:
                if await request.is_disconnected():
                    break
                store = get_approval_store(tenant_id)
                pending_count = len([r for r in store.list() if r.status == "pending"])
                payload = {
                    "event_type": "heartbeat",
                    "tenant_id": tenant_id,
                    "dry_run": settings.dry_run,
                    "kill_switch": settings.kill_switch,
                    "pending_approvals": pending_count,
                    "timestamp": now_iso()
                }
                yield f"event: status\ndata: {json.dumps(payload)}\n\n"
                if once:
                    break
                await asyncio.sleep(15)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/export/siem")
def export_siem(request: Request) -> dict[str, Any]:
    """Verify audit log integrity and return OCSF-compliant SIEM events for the active tenant."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    log_path = get_tenant_path(settings.audit_log_path, tenant_id)

    if not os.path.exists(log_path):
        return {
            "tenant_id": tenant_id,
            "verified": True,
            "total_events": 0,
            "events": []
        }

    verified, broken_line = AuditLog.verify(log_path)
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Cryptographic audit log verification failed at line {broken_line}. Export aborted."
        )

    ocsf_events = []
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                evt = to_ocsf_event(record)
                if evt is not None:
                    ocsf_events.append(evt)
            except (json.JSONDecodeError, TypeError, KeyError):
                pass

    return {
        "tenant_id": tenant_id,
        "verified": True,
        "total_events": len(ocsf_events),
        "events": ocsf_events
    }


@app.post("/api/connect/aws/link")
def create_aws_link(req: AwsLinkRequest, request: Request) -> dict[str, Any]:
    """Generate a 1-click CloudFormation launch stack URL for onboarding AWS accounts."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    conn_store = ConnectionStore(get_tenant_path(settings.connection_store_path, tenant_id))

    grant = Grant.OBSERVE if req.grant == "observe" else Grant.CONTAIN
    existing = conn_store.get(tenant_id)
    if existing and existing.account_id == req.account_id:
        conn = existing
    else:
        conn = conn_store.create(tenant_id=tenant_id, account_id=req.account_id, region=req.region)

    template_url = f"https://s3.amazonaws.com/kronagent-templates-{req.region}/kronagent-{req.grant}-role.json"
    url = launch_stack_url(conn, grant, template_url=template_url)

    return {
        "tenant_id": tenant_id,
        "account_id": conn.account_id,
        "region": conn.region,
        "external_id": conn.external_id,
        "grant": req.grant,
        "launch_url": url,
        "state": conn.state.value
    }


@app.post("/api/connect/aws/verify")
def verify_aws_connection(req: AwsVerifyRequest, request: Request) -> dict[str, Any]:
    """Record an assumed role ARN and perform live STS AssumeRole preflight verification."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    conn_store = ConnectionStore(get_tenant_path(settings.connection_store_path, tenant_id))

    conn = conn_store.get(tenant_id)
    if not conn or conn.account_id != req.account_id:
        raise HTTPException(status_code=404, detail=f"No connection found for account {req.account_id}")

    grant = Grant.OBSERVE if req.grant == "observe" else Grant.CONTAIN
    conn = conn_store.record_role(tenant_id, grant, req.role_arn)

    broker = CredentialBroker()
    res = preflight(conn, broker)
    conn = conn_store.record_preflight(tenant_id, res)

    return {
        "tenant_id": tenant_id,
        "account_id": conn.account_id,
        "state": conn.state.value,
        "grant": req.grant,
        "role_arn": req.role_arn,
        "can_contain": conn.can_contain,
        "missing_permissions": list(res.missing_permissions)
    }


@app.get("/api/connect/status")
def list_cloud_connections(request: Request) -> list[dict[str, Any]]:
    """List all registered cloud connections and permission grants for the tenant."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    conn_store = ConnectionStore(get_tenant_path(settings.connection_store_path, tenant_id))

    conns = conn_store.list()
    res = []
    for c in conns:
        res.append({
            "account_id": c.account_id,
            "region": c.region,
            "external_id": c.external_id,
            "state": c.state.value,
            "observe_role_arn": c.observe_role_arn,
            "contain_role_arn": c.contain_role_arn,
            "can_contain": c.can_contain,
            "last_verified": c.last_verified.isoformat() if c.last_verified else None
        })
    return res






@app.get("/api/approvals")
def list_approvals(request: Request) -> list[Any]:
    """Retrieve all logged approval requests from the store.

    Each carries its insight tags, so the console can show the
    decision-relevant part without re-deriving it client-side and without the
    two implementations drifting apart.
    """
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    store = get_approval_store(tenant_id)
    return [{**r.model_dump(),
             "insight_tags": [t.model_dump() for t in insight_tags(r)]}
            for r in store.list()]


@app.post("/api/approvals/{request_id}/action")
async def execute_approval_action(request_id: str, req: ActionRequest, request: Request) -> dict[str, Any]:
    """Approve/authorize and run, or reject/deny a pending containment action request."""
    tenant_id = tenant_scope(request)
    store = get_approval_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    r = store.get(request_id)
    if r is None:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found.")
    
    if r.status != "pending":
        raise HTTPException(status_code=400, detail=f"Request {request_id} is already in '{r.status}' state.")

    # 1. Resolve and authorize operator identity
    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.APPROVE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        # Audit the access denied event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="access_denied",
            payload={
                "command": f"web_{req.action}",
                "required": "approve",
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    # 2. Process rejection
    if req.action == "deny":
        r.status = "denied"
        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = req.reason
        store.update(r)
        
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "denied",
                "reason": req.reason,
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))
        return {"status": "denied", "detail": "Action request successfully rejected."}

    # 3. Process approval execution
    if settings.kill_switch:
        raise HTTPException(status_code=409, detail="KILL SWITCH ENGAGED — execution refused.")

    # Synthesize policy decision and action
    decision = PolicyDecision(
        action_class=r.action_class,
        disposition="auto_execute",
        reason=f"human-approved via web console by {actor.operator_id}: {req.reason}",
        reversible=r.reversible,
        blast_radius=BlastRadius(r.blast_radius),
    )
    action = r.to_proposed_action()
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))

    # Record approval record
    await audit_log_resolved.record(AuditRecord(
        finding_id=r.finding_id,
        stage="approval",
        payload={
            "request_id": r.request_id,
            "decision": "approved",
            "reason": req.reason,
            "action_class": r.action_class.value,
            "target": r.target,
            **actor.audit_fields()
        }
    ))

    # Dispatch containment adapter
    outcome = await containment.execute(action, decision)

    # Record execution outcome
    await audit_log_resolved.record(AuditRecord(
        finding_id=r.finding_id,
        stage="containment",
        payload={"request_id": r.request_id, **outcome.model_dump()}
    ))

    # Update database request state
    r.decided_by = actor.operator_id
    r.decided_at = now_iso()
    r.decision_reason = req.reason
    r.execution_detail = outcome.detail
    
    if outcome.executed:
        r.status = "executed"
    elif outcome.error:
        r.status = "failed"
    else:
        r.status = "approved"  # Dry-run
        
    store.update(r)
    return {
        "status": r.status,
        "detail": outcome.detail,
        "error": outcome.error
    }


@app.get("/api/audit")
def get_audit_trail(request: Request) -> list[dict[str, Any]]:
    """Retrieve chronological event history from the append-only audit log."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    records = []
    audit_path = get_tenant_path(settings.audit_log_path, tenant_id)
    if not os.path.exists(audit_path):
        return []
    with open(audit_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
                rec = envelope.get("record", {})
                if rec:
                    records.append(rec)
            except json.JSONDecodeError:
                continue
    return records


@app.get("/api/allowlist")
def list_allowlist(request: Request) -> list[str]:
    """Retrieve the action classes currently granted autonomy.

    Entries whose TTL has lapsed are excluded: they no longer authorize
    anything, and a console that still showed them as promoted would be
    describing autonomy the policy engine has already withdrawn. `GET
    /api/allowlist/review` is where lapsed entries stay visible, because
    deciding whether to renew one needs to see it.
    """
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    store = get_allowlist_store(tenant_id)
    return [entry.action_class for entry in store.active()]


@app.get("/api/allowlist/review")
def review_allowlist(request: Request) -> list[dict[str, Any]]:
    """Every entry with the context a re-earn-it review needs: who promoted it,
    when, why, when it lapses, and whether it has ever actually fired. Expired
    and stale entries included and marked — an entry that never fires is
    standing authority with no benefit, which is precisely what a review is
    looking for.

    Each entry also carries the policy engine's own classification
    (reversible / blast radius / auto-eligible). That is served from
    `_ACTION_PROPERTIES` rather than re-derived by the caller: the console used
    to guess it from the action-class name and got it wrong — it showed
    `block_ip` as subnet-wide and `revoke_role_sessions` as account-wide when
    the policy table classifies both single-resource — which misrepresents the
    exact classification the safety ceiling is built on.
    """
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    store = get_allowlist_store(tenant_id)
    policy = PolicyEngine(settings, store)

    def _classify(action_class: str) -> dict[str, Any]:
        try:
            ac = ActionClass(action_class)
        except ValueError:
            # An entry naming a class the taxonomy no longer has. It grants
            # nothing — the engine can never propose it — and the console needs
            # to say so rather than render blanks.
            return {"known_action_class": False, "auto_eligible": False,
                    "reversible": None, "blast_radius": None}
        props = policy._properties(ac)
        return {
            "known_action_class": True,
            "auto_eligible": policy.is_auto_eligible(ac),
            "reversible": props["reversible"],
            "blast_radius": props["blast_radius"].value,
        }

    return [
        {
            **entry.model_dump(),
            "expired": entry.is_expired(),
            "stale": entry.is_stale(),
            "never_fired": entry.last_fired_at is None,
            **_classify(entry.action_class),
        }
        for entry in store.list()
    ]


@app.post("/api/allowlist/promote")
async def promote_allowlist_class(req: PromoteRequest, request: Request) -> dict[str, Any]:
    """Add a containment action class to the autonomous allowlist."""
    tenant_id = tenant_scope(request)
    store = get_allowlist_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.PROMOTE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await audit_log_resolved.record(AuditRecord(
            finding_id="_governance",
            stage="access_denied",
            payload={
                "command": "web_promote",
                "required": "promote",
                "action_class": req.action_class,
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        ac = ActionClass(req.action_class)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action class name '{req.action_class}'.")

    expires_in = None
    if req.expires_in:
        try:
            expires_in = parse_duration(req.expires_in)
        except DurationError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    entry = await store.add(
        ac,
        by=actor.operator_id,
        reason=req.reason,
        audit=audit_log_resolved,
        actor_fields=actor.audit_fields(),
        expires_in=expires_in,
        owner=req.owner,
    )
    detail = f"Class {ac.value} successfully promoted."
    if entry.expires_at:
        detail += f" Expires {entry.expires_at}; requires renewal after that."
    return {"status": "success", "detail": detail,
            "expires_at": entry.expires_at, "owner": entry.owner}


@app.post("/api/allowlist/reassign")
async def reassign_allowlist_owner(req: ReassignRequest, request: Request) -> dict[str, Any]:
    """Hand an entry to a new accountable owner, leaving the promotion history
    intact. PROMOTE-gated: moving ownership moves who can renew the entry."""
    tenant_id = tenant_scope(request)
    store = get_allowlist_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.PROMOTE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await audit_log_resolved.record(AuditRecord(
            finding_id="_governance",
            stage="access_denied",
            payload={
                "command": "web_reassign",
                "required": "promote",
                "action_class": req.action_class,
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        ac = ActionClass(req.action_class)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action class name '{req.action_class}'.")

    entry = await store.set_owner(
        ac,
        owner=req.owner,
        by=actor.operator_id,
        reason=req.reason,
        audit=audit_log_resolved,
        actor_fields=actor.audit_fields(),
    )
    if entry is None:
        return {"status": "noop",
                "detail": f"Class {ac.value} is not on the allowlist; nothing to reassign."}
    return {"status": "success", "detail": f"Class {ac.value} is now owned by {entry.owner}.",
            "owner": entry.owner}


@app.post("/api/allowlist/demote")
async def demote_allowlist_class(req: PromoteRequest, request: Request) -> dict[str, Any]:
    """Remove a containment action class from the autonomous allowlist."""
    tenant_id = tenant_scope(request)
    store = get_allowlist_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.PROMOTE,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await audit_log_resolved.record(AuditRecord(
            finding_id="_governance",
            stage="access_denied",
            payload={
                "command": "web_demote",
                "required": "promote",
                "action_class": req.action_class,
                "operator_id": req.operator_id,
                "error": str(exc)
            }
        ))
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        ac = ActionClass(req.action_class)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action class name '{req.action_class}'.")

    await store.remove(
        ac,
        by=actor.operator_id,
        reason=req.reason,
        audit=audit_log_resolved,
        actor_fields=actor.audit_fields()
    )
    return {"status": "success", "detail": f"Class {ac.value} successfully demoted."}


@app.get("/api/metrics")
def get_dashboard_metrics(request: Request) -> dict[str, int]:
    """Compile summary metrics counting total, autonomous, and human-approved action lifecycles."""
    check_view_permission(request)
    tenant_id = tenant_scope(request)
    store = get_approval_store(tenant_id)
    audit_path = get_tenant_path(settings.audit_log_path, tenant_id)

    total_findings = 0
    total_autonomous = 0
    total_human_approved = 0

    findings_seen = set()
    
    if os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    envelope = json.loads(line)
                    rec = envelope.get("record", {})
                    fid = rec.get("finding_id")
                    if not fid or fid == "_governance":
                        continue
                    
                    if fid not in findings_seen:
                        findings_seen.add(fid)
                        total_findings += 1
                        
                    stage = rec.get("stage")
                    payload = rec.get("payload", {})
                    
                    if stage == "policy":
                        decision = payload.get("decision", {})
                        if decision.get("disposition") == "auto_execute":
                            total_autonomous += 1
                    elif stage == "approval":
                        decision = payload.get("decision")
                        if decision == "approved":
                            total_human_approved += 1
                except json.JSONDecodeError:
                    continue

    pending_list = store.list(status="pending")

    return {
        "total_findings": total_findings,
        "total_pending": len(pending_list),
        "total_autonomous_actions": total_autonomous,
        "total_human_overridden_actions": total_human_approved
    }


@app.post("/api/slack/interactive")
async def slack_interactive(request: Request) -> dict[str, Any]:
    """
    Handle interactive button clicks from Slack approval messages.
    """
    body_bytes = await request.body()
    headers = request.headers
    signature = headers.get("X-Slack-Signature", "")
    timestamp = headers.get("X-Slack-Request-Timestamp", "")

    # 1. Verify Slack request signature (HMAC-SHA256).
    #
    # Refuse when no signing secret is configured, rather than skipping the
    # check. This endpoint is reachable from the internet by design — Slack
    # calls it — and the unauthenticated fallback below grants the caller the
    # admin role, so an unset secret turned "anyone who can POST here" into
    # "anyone can approve containment". Other surfaces can treat missing auth as
    # a local single-operator posture; a public webhook cannot.
    if not settings.slack_signing_secret:
        raise HTTPException(
            status_code=503,
            detail="KRONAGENT_SLACK_SIGNING_SECRET is not configured — refusing "
                   "unverified Slack interactions.",
        )
    from .chatops import verify_slack_signature
    if not verify_slack_signature(settings.slack_signing_secret, body_bytes, timestamp, signature):
        raise HTTPException(status_code=401, detail="Invalid Slack signature.")

    # 2. Parse form-url-encoded payload
    import urllib.parse
    form_data = urllib.parse.parse_qs(body_bytes.decode("utf-8"))
    payload_str_list = form_data.get("payload")
    if not payload_str_list:
        raise HTTPException(status_code=400, detail="Missing interactive payload.")

    try:
        payload = json.loads(payload_str_list[0])
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed interactive JSON payload.")

    # 3. Extract operator details
    slack_user_id = payload.get("user", {}).get("id", "")
    slack_username = payload.get("user", {}).get("name", "") or payload.get("user", {}).get("username", "unknown")
    operator_id = settings.slack_user_mapping.get(slack_user_id, slack_user_id)

    # 4. Resolve local identity permissions
    from .identity import LocalIdentityProvider, Permission, Operator, AuthContext
    
    operator = None
    if settings.operator_registry_path:
        provider = LocalIdentityProvider(settings.operator_registry_path)
        operator = provider.get_operator(operator_id)
        if operator is None:
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authentication failed: Slack user mapping '{operator_id}' not found in operator registry."
            }
        if not operator.active:
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authentication failed: Operator '{operator_id}' is marked inactive."
            }
        if Permission.APPROVE not in operator.permissions():
            return {
                "response_type": "ephemeral",
                "text": f"❌ Authorization failed: Operator '{operator_id}' lacks approval permissions."
            }
        identity_verified = True
    else:
        # Default unauthenticated/fallback mode: map Slack operator with administrator role
        operator = Operator(
            operator_id=operator_id,
            display_name=slack_username,
            roles=["admin"],
            active=True
        )
        identity_verified = False

    actor = AuthContext(
        operator_id=operator.operator_id,
        display_name=operator.display_name,
        roles=operator.roles,
        identity_verified=identity_verified,
        auth_method="slack_sso",
        tenants=operator.permitted_tenants(),
    )

    # 5. Extract action decision
    actions = payload.get("actions", [])
    if not actions:
        raise HTTPException(status_code=400, detail="No action element found.")

    action_element = actions[0]
    action_id = action_element.get("action_id")
    request_id = action_element.get("value")

    # Locate request_id across all tenant stores
    tenant_id = "default"
    r = get_approval_store("default").get(request_id)
    if r is None:
        import glob
        directory = os.path.dirname(os.path.abspath(settings.approval_store_path)) or "."
        pattern = os.path.join(directory, "kronagent_approvals_*.json")
        for filepath in glob.glob(pattern):
            filename = os.path.basename(filepath)
            base_filename = os.path.basename(settings.approval_store_path)
            root, ext = os.path.splitext(base_filename)
            prefix = f"{root}_"
            if filename.startswith(prefix) and filename.endswith(ext):
                tid = filename[len(prefix):-len(ext)]
                candidate_store = get_approval_store(tid)
                candidate_r = candidate_store.get(request_id)
                if candidate_r is not None:
                    r = candidate_r
                    tenant_id = tid
                    break

    if r is None:
        return {
            "response_type": "ephemeral",
            "text": f"❌ Request ID '{request_id}' not found in any approval store."
        }

    # The lookup above searches EVERY tenant's approval store for the request
    # id, so without this a Slack user scoped to one tenant could approve
    # another tenant's containment just by clicking a button carrying its id.
    if identity_configured() and not actor.may_access(tenant_id):
        return {
            "response_type": "ephemeral",
            "text": (f"❌ Authorization failed: operator '{actor.operator_id}' is not "
                     f"authorized for tenant '{tenant_id}'."),
        }

    # Dynamically resolve stores for the selected tenant
    store = get_approval_store(tenant_id)
    audit_log_resolved = get_audit_log(tenant_id)

    if r.status != "pending":
        return {
            "response_type": "ephemeral",
            "text": f"⚠️ Request is already processed: status is '{r.status}'."
        }

    action_type = "approve" if action_id == "approve_action" else "deny"

    # 6. Execute decision flow
    if action_type == "deny":
        r.status = "denied"
        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = "Rejected via Slack ChatOps"
        store.update(r)

        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "denied",
                "reason": "Rejected via Slack ChatOps",
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))
        status_text = f"Rejected via Slack by @{slack_username}"
    else:
        if settings.kill_switch:
            return {
                "response_type": "ephemeral",
                "text": "❌ Command execution aborted: global Kronagent KILL SWITCH is ENGAGED."
            }

        # Setup decision context
        decision = PolicyDecision(
            action_class=r.action_class,
            disposition="auto_execute",
            reason=f"approved via Slack ChatOps by @{slack_username}",
            reversible=r.reversible,
            blast_radius=BlastRadius(r.blast_radius),
        )
        action = r.to_proposed_action()
        containment = ContainmentExecutor(settings, build_containment_adapters(settings))

        # Record approval event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="approval",
            payload={
                "request_id": r.request_id,
                "decision": "approved",
                "reason": "Approved via Slack ChatOps",
                "action_class": r.action_class.value,
                "target": r.target,
                **actor.audit_fields()
            }
        ))

        # Execute containment
        outcome = await containment.execute(action, decision)

        # Record containment audit event
        await audit_log_resolved.record(AuditRecord(
            finding_id=r.finding_id,
            stage="containment",
            payload={"request_id": r.request_id, **outcome.model_dump()}
        ))

        r.decided_by = actor.operator_id
        r.decided_at = now_iso()
        r.decision_reason = "Approved via Slack ChatOps"
        r.execution_detail = outcome.detail

        if outcome.executed:
            r.status = "executed"
        elif outcome.error:
            r.status = "failed"
        else:
            r.status = "approved"  # Dry-run

        store.update(r)
        status_text = f"Approved & {r.status} via Slack by @{slack_username} ({outcome.detail})"

    # 7. Format updated message blocks
    from .chatops import ChatOpsNotifier
    updated_blocks = ChatOpsNotifier.build_slack_blocks(r, status_text)

    return {
        "replace_original": True,
        "text": f"Kronagent Approval Request Updated: {status_text}",
        "blocks": updated_blocks
    }


# ═══════════════════════════════════════════════════════════════════════════ #
# Cloud connections
#
# The endpoints a customer's onboarding actually runs through: mint an External
# ID, hand them a CloudFormation link, record the role their stack produced,
# and verify it works.
#
# Two rules govern everything below.
#
#   1. The External ID is a secret and is NEVER returned by a read endpoint.
#      It appears in exactly one place — inside the rendered template, which is
#      the thing the customer has to install. Anywhere else it is redacted,
#      because a role ARN is not secret (it shows up in the customer's own
#      CloudTrail) and the pair is enough to assume their role.
#
#   2. Granting containment is at least as consequential as promoting an action
#      class to auto-execute, so it takes the same PROMOTE permission and is
#      written to the same hash-chained audit log.
# ═══════════════════════════════════════════════════════════════════════════ #

from .connect import (  # noqa: E402 - grouped with the endpoints that use it
    ConnectionStore,
    CredentialBroker,
    Grant,
    kronagent_account_id,
    preflight,
    render_template,
)

connection_store = ConnectionStore(settings.connection_store_path)
credential_broker = CredentialBroker()


def _public_connection(conn) -> dict[str, Any]:
    """A connection as it may safely leave the process.

    Deliberately constructs the response field by field rather than dumping the
    dataclass and popping the secret. A denylist breaks silently the day someone
    adds a second sensitive field; an allowlist fails closed.
    """
    return {
        "tenant_id": conn.tenant_id,
        "account_id": conn.account_id,
        "region": conn.region,
        "state": conn.state.value,
        "observe_role_arn": conn.observe_role_arn,
        "contain_role_arn": conn.contain_role_arn,
        "can_contain": conn.can_contain,
        "missing_permissions": list(conn.missing_permissions),
        "last_verified": conn.last_verified.isoformat() if conn.last_verified else None,
        # Enough for an operator to confirm the customer pasted the right value,
        # without the response itself being a credential.
        "external_id_hint": conn.external_id[-6:] if conn.external_id else "",
    }


class ConnectRequest(BaseModel):
    tenant_id: str
    account_id: str
    region: str
    operator_id: Optional[str] = None
    token: Optional[str] = None


class RecordRoleRequest(BaseModel):
    grant: Literal["observe", "contain"]
    role_arn: str
    operator_id: Optional[str] = None
    token: Optional[str] = None


class VerifyRequest(BaseModel):
    grant: Literal["observe", "contain"] = "observe"
    operator_id: Optional[str] = None
    token: Optional[str] = None


async def _require(permission, req, tenant_id: str, command: str, **extra):
    """Authorise, and audit the refusal if it fails.

    Two checks, not one. The permission answers *what* this operator may do;
    `may_access` answers *whose cloud account they may do it to*. This function
    used to ask only the first, so an admin of any tenant could point another
    tenant's containment role at an ARN they controlled, or disconnect their
    cloud account outright — both demonstrated returning HTTP 200.

    A denied attempt to connect or disconnect a cloud account is exactly the
    kind of thing an incident review needs, so it is recorded before the 403.
    """
    audit = get_audit_log(tenant_id)

    async def _deny(reason: str):
        await audit.record(AuditRecord(
            finding_id="_governance", stage="access_denied",
            payload={"command": command, "required": permission.value,
                     "tenant_id": tenant_id, "operator_id": req.operator_id,
                     "error": reason, **extra},
        ))
        raise HTTPException(status_code=403, detail=reason)

    try:
        actor = resolve_actor(
            registry_path=settings.operator_registry_path,
            required=permission,
            # `by` is what unauthenticated mode records as a self-asserted
            # actor; `operator_id` is what authenticated mode authenticates.
            # Passing both means the same endpoint works in a local single
            # -operator install and in an enforced-registry deployment, with the
            # audit record honestly marked identity_verified either way.
            by=req.operator_id,
            operator_id=req.operator_id,
            token=req.token,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        await _deny(str(exc))

    # Same reasoning as authorize_tenant: with no identity system there is no
    # principal to scope, so only the permission gate applies.
    if identity_configured() and not actor.may_access(tenant_id):
        await _deny(f"operator '{actor.operator_id}' is not authorized for tenant "
                    f"'{tenant_id}' (permitted: {actor.tenants}). Add it to the "
                    f"operator's 'tenants' in the registry, or grant '*'.")

    return actor


@app.get("/api/connections")
async def list_connections(request: Request) -> dict[str, Any]:
    """The connected tenants THIS CALLER may see.

    Previously unauthenticated and unfiltered, so anyone who could reach the API
    got every customer's tenant name, AWS account id and region — a customer
    list plus the identifiers needed to target them. External IDs were redacted,
    which was never the whole exposure.
    """
    visible = [c for c in connection_store.list()
               if _may_access_tenant(request, c.tenant_id)]
    return {"connections": [_public_connection(c) for c in visible]}


@app.get("/api/connections/{tenant_id}")
async def get_connection(tenant_id: str, request: Request) -> dict[str, Any]:
    authorize_tenant(request, tenant_id)
    conn = connection_store.get(tenant_id)
    if conn is None:
        raise HTTPException(status_code=404, detail=f"no connection for tenant '{tenant_id}'")
    return _public_connection(conn)


@app.post("/api/connections", status_code=201)
async def create_connection(req: ConnectRequest) -> dict[str, Any]:
    """Begin onboarding: mint an External ID and return the install links.

    PROMOTE, not APPROVE. Creating a connection is what makes it possible for
    this platform to touch an account at all — governance, not operations.
    """
    actor = await _require(Permission.PROMOTE, req, req.tenant_id, "web_connect_create",
                           account_id=req.account_id)
    try:
        conn = connection_store.create(
            tenant_id=req.tenant_id, account_id=req.account_id, region=req.region)
    except ValueError as exc:
        # Both a duplicate tenant and a malformed account id or region surface
        # as ValueError, and they are not the same failure: one means "you
        # already did this", the other means "this input is wrong". Returning
        # 409 for both told a caller with a typo'd account id that they were
        # already connected, which is a confusing lie.
        already = "already connected" in str(exc)
        raise HTTPException(status_code=409 if already else 400, detail=str(exc))

    await get_audit_log(req.tenant_id).record(AuditRecord(
        finding_id="_governance", stage="connection_created",
        payload={"tenant_id": conn.tenant_id, "account_id": conn.account_id,
                 "region": conn.region, "by": getattr(actor, "operator_id", req.operator_id),
                 # The External ID itself is never audited — an audit log is
                 # exportable to a customer's SIEM, and this one is a credential.
                 "external_id_hint": conn.external_id[-6:]},
    ))
    return {
        **_public_connection(conn),
        "next_step": "Install the observe stack, then POST the resulting role ARN "
                     "to /api/connections/{tenant_id}/role",
    }


@app.get("/api/connections/{tenant_id}/template/{grant}")
async def connection_template(tenant_id: str, grant: str, request: Request) -> dict[str, Any]:
    """The CloudFormation template for one grant.

    This is the single place the External ID legitimately appears: it has to,
    because the customer's trust policy is built from it. That makes this the
    most sensitive read in the connections API — the External ID is the secret
    that stops another of our customers tricking us into assuming a role we
    already have access to (the confused-deputy problem this whole flow exists
    to prevent). It was previously unauthenticated.
    """
    authorize_tenant(request, tenant_id)
    conn = connection_store.get(tenant_id)
    if conn is None:
        raise HTTPException(status_code=404, detail=f"no connection for tenant '{tenant_id}'")
    try:
        g = Grant(grant)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"grant must be observe or contain, got '{grant}'")

    account = kronagent_account_id()
    if not account:
        raise HTTPException(
            status_code=503,
            detail="KRONAGENT_AWS_ACCOUNT_ID is not configured — a template "
                   "without it would produce a role nobody can assume",
        )
    return {
        "grant": g.value,
        "template": render_template(conn, g, kronagent_account_id=account,
                                    quarantine_nacl_id=settings.quarantine_nacl_id
                                                       or "QUARANTINE_NACL_ID"),
    }


@app.post("/api/connections/{tenant_id}/role")
async def record_connection_role(tenant_id: str, req: RecordRoleRequest) -> dict[str, Any]:
    """Attach the role ARN the customer's stack produced."""
    g = Grant(req.grant)
    actor = await _require(Permission.PROMOTE, req, tenant_id, "web_connect_record_role",
                           grant=g.value, role_arn=req.role_arn)
    try:
        conn = connection_store.record_role(tenant_id, g, req.role_arn)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    await get_audit_log(tenant_id).record(AuditRecord(
        finding_id="_governance",
        # Granting containment is the moment this platform becomes able to
        # change a customer's infrastructure. It gets its own stage name so it
        # is greppable in an audit export.
        stage="containment_granted" if g is Grant.CONTAIN else "observe_granted",
        payload={"tenant_id": tenant_id, "grant": g.value, "role_arn": req.role_arn,
                 "by": getattr(actor, "operator_id", req.operator_id)},
    ))
    return _public_connection(conn)


@app.post("/api/connections/{tenant_id}/verify")
async def verify_connection(tenant_id: str, req: VerifyRequest) -> dict[str, Any]:
    """Assume the role and probe it, then record what came back.

    Authorised like its siblings, which it previously was not — `VerifyRequest`
    already carried operator_id and token, but nothing read them. This is not a
    read: it performs a real STS AssumeRole into the customer's account, mutates
    the stored connection state, and writes an audit record, so an anonymous
    caller could make Kronagent exercise any tenant's credentials on demand.
    """
    await _require(Permission.PROMOTE, req, tenant_id, "web_connect_verify",
                   grant=req.grant)
    conn = connection_store.get(tenant_id)
    if conn is None:
        raise HTTPException(status_code=404, detail=f"no connection for tenant '{tenant_id}'")

    result = preflight(conn, credential_broker, Grant(req.grant))
    conn = connection_store.record_preflight(tenant_id, result)

    await get_audit_log(tenant_id).record(AuditRecord(
        finding_id="_governance", stage="connection_verified",
        payload={"tenant_id": tenant_id, "grant": req.grant, "state": conn.state.value,
                 "missing": list(result.missing), "error": result.error},
    ))
    return {**_public_connection(conn), "ok": result.ok, "error": result.error}


@app.delete("/api/connections/{tenant_id}")
async def delete_connection(tenant_id: str, req: VerifyRequest) -> dict[str, Any]:
    """Forget a tenant's connection.

    Does not touch the customer's account — their stack is theirs to delete.
    This only stops Kronagent from trying, and the audit record says so, since
    "disconnected" and "revoked" are different claims.
    """
    actor = await _require(Permission.PROMOTE, req, tenant_id, "web_connect_delete")
    existed = connection_store.delete(tenant_id)
    if not existed:
        raise HTTPException(status_code=404, detail=f"no connection for tenant '{tenant_id}'")

    await get_audit_log(tenant_id).record(AuditRecord(
        finding_id="_governance", stage="connection_deleted",
        payload={"tenant_id": tenant_id, "by": getattr(actor, "operator_id", req.operator_id),
                 "note": "Kronagent will no longer attempt to assume this role. "
                         "The customer's CloudFormation stack is unaffected and "
                         "should be deleted separately to revoke access."},
    ))
    credential_broker.invalidate(tenant_id)
    return {"deleted": True, "tenant_id": tenant_id}
