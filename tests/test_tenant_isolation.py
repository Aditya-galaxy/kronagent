"""
Tenant isolation, and the refusal to report containment that did not happen.

Two defects found by auditing the running system rather than reading it. Both
were demonstrated end to end before being fixed, and both are pinned here.

**1. Cross-tenant access (OWASP A01).** The tenant came from a client-supplied
`?tenant_id=` / `X-Tenant-ID`, and `identity.py` had no concept of a tenant at
all — so nothing could bind an operator to one. An authenticated admin of any
tenant could read another tenant's incidents and *approve its production
containment*:

    HTTP 200  {'status': 'approved',
               'detail': 'would auto-execute: deactivate access key AKIA-ACME-PRODUCTION'}
    decided_by = evilcorp-admin

RBAC answered "what may this operator do" and was complete. Nothing answered
"whose data may they do it to." Both questions have to be asked.

**2. False containment reporting.** GCP's `perform()` updated an in-memory set
and returned a success string without calling GCP. In live mode the executor saw
no exception and wrote `executed=True`, "EXECUTED — service account key ... set
to disabled" into the hash-chained audit log — so a live credential was
certified as revoked in signed compliance evidence. An absent capability gets
noticed; a falsely-reported one does not.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json

import pytest

from kronagent.identity import (
    ALL_TENANTS,
    DEFAULT_TENANT,
    AuthContext,
    LocalIdentityProvider,
    Operator,
    hash_token,
)
from kronagent.schemas import ActionClass, BlastRadius, PolicyDecision, ProposedAction

# --------------------------------------------------------------------------- #
# The identity -> tenant binding
# --------------------------------------------------------------------------- #

def _ctx(tenants: list[str]) -> AuthContext:
    return AuthContext(operator_id="op", display_name="Op", roles=["admin"],
                       identity_verified=True, auth_method="local_token", tenants=tenants)


def test_operator_may_access_its_own_tenant() -> None:
    assert _ctx(["acme"]).may_access("acme")


def test_operator_may_not_access_another_tenant() -> None:
    """The exact escalation that was demonstrated against the live API."""
    assert not _ctx(["evilcorp"]).may_access("acme")


def test_wildcard_grants_every_tenant() -> None:
    """For a platform/MSSP operator. Spelled explicitly so granting it is a
    visible registry decision, never an accident of an omitted field."""
    assert _ctx([ALL_TENANTS]).may_access("acme")
    assert _ctx([ALL_TENANTS]).may_access("anything-at-all")


def test_empty_tenants_means_default_only_not_everything() -> None:
    """The safe reading of an unset field. Treating empty as 'all' would have
    made every pre-existing registry silently cross-tenant on upgrade."""
    ctx = _ctx([])
    assert ctx.may_access(DEFAULT_TENANT)
    assert not ctx.may_access("acme")


def test_unauthenticated_actor_is_confined_to_the_default_tenant() -> None:
    from kronagent.identity import Permission, resolve_actor

    actor = resolve_actor(registry_path="", required=Permission.APPROVE, by="alice")
    assert actor.identity_verified is False
    assert not actor.may_access("acme")


def test_registry_tenants_are_loaded(tmp_path) -> None:
    path = tmp_path / "ops.json"
    path.write_text(json.dumps({"alice": {
        "display_name": "Alice", "roles": ["admin"],
        "token_sha256": hash_token("t"), "active": True, "tenants": ["acme", "beta"],
    }}))
    operator = LocalIdentityProvider(str(path)).get_operator("alice")
    assert operator.permitted_tenants() == ["acme", "beta"]


def test_registry_without_tenants_defaults_to_the_default_tenant(tmp_path) -> None:
    """Back-compat: an existing single-tenant registry keeps working."""
    path = tmp_path / "ops.json"
    path.write_text(json.dumps({"alice": {
        "display_name": "Alice", "roles": ["admin"],
        "token_sha256": hash_token("t"), "active": True,
    }}))
    assert LocalIdentityProvider(str(path)).get_operator("alice").permitted_tenants() == [DEFAULT_TENANT]


def test_audit_fields_record_the_tenant_scope() -> None:
    """An auditor must be able to see which tenant scope authorised a decision,
    not merely which operator made it."""
    assert _ctx(["acme"]).audit_fields()["tenants"] == ["acme"]


def test_operator_model_defaults_are_narrow() -> None:
    assert Operator(operator_id="x", display_name="X").permitted_tenants() == [DEFAULT_TENANT]


# --------------------------------------------------------------------------- #
# Enforcement at the HTTP boundary
# --------------------------------------------------------------------------- #

@pytest.fixture
def api(tmp_path, monkeypatch):
    """A console wired to a two-tenant registry, driven over real HTTP."""
    registry = tmp_path / "ops.json"
    registry.write_text(json.dumps({
        "acme-admin": {"display_name": "Acme", "roles": ["admin"],
                       "token_sha256": hash_token("acme-tok"), "active": True,
                       "tenants": ["acme"]},
        "evil-admin": {"display_name": "Evil", "roles": ["admin"],
                       "token_sha256": hash_token("evil-tok"), "active": True,
                       "tenants": ["evilcorp"]},
        "platform-admin": {"display_name": "Platform", "roles": ["admin"],
                           "token_sha256": hash_token("plat-tok"), "active": True,
                           "tenants": [ALL_TENANTS]},
    }))
    for var, val in [
        ("KRONAGENT_OPERATOR_REGISTRY", str(registry)),
        ("KRONAGENT_APPROVAL_PATH", str(tmp_path / "appr.json")),
        ("KRONAGENT_ALLOWLIST_PATH", str(tmp_path / "allow.json")),
        ("KRONAGENT_AUDIT_PATH", str(tmp_path / "audit.jsonl")),
    ]:
        monkeypatch.setenv(var, val)

    import importlib

    from fastapi.testclient import TestClient

    from kronagent import web
    importlib.reload(web)

    # A pending containment action belonging to tenant "acme".
    from kronagent.approvals import ApprovalRequest, ApprovalStore
    from kronagent.orchestrator import get_tenant_path
    store = ApprovalStore(get_tenant_path(str(tmp_path / "appr.json"), "acme"))
    store.add(ApprovalRequest(
        finding_id="acme-secret-001", finding_type="CredentialExfiltration", severity=9.0,
        provider="aws", action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA-ACME-PRODUCTION", rationale="ACME confidential incident",
        policy_reason="x", reversible=True, blast_radius="single_resource"))

    yield TestClient(web.app)
    importlib.reload(web)


ACME = {"X-Operator-ID": "acme-admin", "X-Operator-Token": "acme-tok"}
EVIL = {"X-Operator-ID": "evil-admin", "X-Operator-Token": "evil-tok"}
PLATFORM = {"X-Operator-ID": "platform-admin", "X-Operator-Token": "plat-tok"}


def test_anonymous_cannot_read_another_tenant(api) -> None:
    """Naming a non-default tenant requires identity even when require_view_auth
    is off — otherwise that setting silently exposes every tenant."""
    r = api.get("/api/approvals?tenant_id=acme")
    assert r.status_code == 403


def test_operator_cannot_read_another_tenants_queue(api) -> None:
    r = api.get("/api/approvals?tenant_id=acme", headers=EVIL)
    assert r.status_code == 403
    assert "not authorized for tenant" in r.json()["detail"]


def test_operator_can_read_its_own_tenant(api) -> None:
    r = api.get("/api/approvals?tenant_id=acme", headers=ACME)
    assert r.status_code == 200
    assert r.json()[0]["finding_id"] == "acme-secret-001"


def test_platform_operator_may_read_any_tenant(api) -> None:
    assert api.get("/api/approvals?tenant_id=acme", headers=PLATFORM).status_code == 200


def test_operator_cannot_approve_another_tenants_containment(api) -> None:
    """THE regression test. This exact request previously returned 200 and
    approved a production key revocation in a tenant the caller had no
    relationship with."""
    rid = api.get("/api/approvals?tenant_id=acme", headers=ACME).json()[0]["request_id"]

    r = api.post(f"/api/approvals/{rid}/action?tenant_id=acme", headers=EVIL,
                 json={"action": "approve", "operator_id": "evil-admin",
                       "token": "evil-tok", "reason": "not my tenant"})
    assert r.status_code == 403

    after = api.get("/api/approvals?tenant_id=acme&status=all", headers=ACME).json()
    assert after[0]["status"] == "pending", "the action was approved across tenants"


def test_the_header_route_is_guarded_too(api) -> None:
    """X-Tenant-ID is the other way in; guarding only the query parameter would
    leave the same hole one header away."""
    assert api.get("/api/approvals", headers={**EVIL, "X-Tenant-ID": "acme"}).status_code == 403


def test_default_tenant_behaviour_is_unchanged(api) -> None:
    """Single-tenant deployments must not need credentials they never had."""
    assert api.get("/api/approvals").status_code == 200


# --------------------------------------------------------------------------- #
# GCP must not report containment it did not perform
# --------------------------------------------------------------------------- #

def _gcp_action() -> ProposedAction:
    return ProposedAction(provider="gcp", action_class=ActionClass.DISABLE_SERVICE_ACCOUNT_KEY,
                          target="COMPROMISED-KEY-abc123", rationale="credential exfiltration")


async def test_gcp_live_execution_refuses_rather_than_faking_success() -> None:
    from kronagent.providers.gcp import GcpContainmentAdapter

    with pytest.raises(NotImplementedError, match="was NOT performed"):
        await GcpContainmentAdapter().perform(_gcp_action())


async def test_gcp_executor_records_failure_not_execution() -> None:
    """What the audit log ends up saying — the part that actually mattered.
    Previously: executed=True, error=None, 'EXECUTED — key set to disabled',
    with the key still live."""
    from kronagent.config import Settings
    from kronagent.containment import ContainmentExecutor
    from kronagent.providers import build_containment_adapters

    settings = Settings(dry_run=False)
    executor = ContainmentExecutor(settings, build_containment_adapters(settings))
    decision = PolicyDecision(action_class=ActionClass.DISABLE_SERVICE_ACCOUNT_KEY,
                              disposition="auto_execute", reason="allowlisted",
                              reversible=True, blast_radius=BlastRadius.SINGLE_RESOURCE)

    outcome = await executor.execute(_gcp_action(), decision)

    assert outcome.executed is False
    assert outcome.error
    assert "EXECUTION FAILED" in outcome.detail
    assert "set to disabled" not in outcome.detail


def test_the_shipped_gcp_adapter_does_not_simulate() -> None:
    """build_containment_adapters must never hand a deployment the simulating
    adapter — that is the whole defect, expressed as configuration."""
    from kronagent.config import Settings
    from kronagent.providers import build_containment_adapters

    assert build_containment_adapters(Settings())["gcp"]._simulate is False


async def test_simulation_still_available_for_tests() -> None:
    from kronagent.providers.gcp import GcpContainmentAdapter

    adapter = GcpContainmentAdapter(simulate=True)
    detail, _ = await adapter.perform(_gcp_action())
    assert "COMPROMISED-KEY-abc123" in adapter.disabled_keys
    assert "set to disabled" in detail


def test_gcp_planning_is_unaffected() -> None:
    """Dry-run must still show exactly the API calls a real implementation
    would make; only execution refuses."""
    from kronagent.providers.gcp import GcpContainmentAdapter

    calls, rollback, detail = GcpContainmentAdapter().plan(_gcp_action())
    assert "serviceAccountKeys.disable" in calls[0]
    assert "serviceAccountKeys.enable" in rollback


# --------------------------------------------------------------------------- #
# The connections API — a second surface with the same hole, plus unauthenticated
# reads. All three were demonstrated against the running app before being fixed:
#
#   A. anonymous GET /api/connections returned every tenant's name, AWS account
#      id and region — a customer list plus the identifiers to target them.
#   B. an admin of one tenant repointed another tenant's contain_role_arn at an
#      attacker-controlled ARN (HTTP 200) — defeating the External ID that the
#      whole connect flow exists to protect.
#   C. an admin of one tenant DELETED another tenant's cloud connection.
# --------------------------------------------------------------------------- #

@pytest.fixture
def connect_api(tmp_path, monkeypatch):
    registry = tmp_path / "ops.json"
    registry.write_text(json.dumps({
        "acme-admin": {"display_name": "Acme", "roles": ["admin"],
                       "token_sha256": hash_token("acme-tok"), "active": True,
                       "tenants": ["acme"]},
        "evil-admin": {"display_name": "Evil", "roles": ["admin"],
                       "token_sha256": hash_token("evil-tok"), "active": True,
                       "tenants": ["evilcorp"]},
    }))
    for var, val in [
        ("KRONAGENT_OPERATOR_REGISTRY", str(registry)),
        ("KRONAGENT_CONNECTION_PATH", str(tmp_path / "conn.json")),
        ("KRONAGENT_AUDIT_PATH", str(tmp_path / "audit.jsonl")),
        ("KRONAGENT_APPROVAL_PATH", str(tmp_path / "appr.json")),
        ("KRONAGENT_ALLOWLIST_PATH", str(tmp_path / "allow.json")),
    ]:
        monkeypatch.setenv(var, val)

    import importlib

    from fastapi.testclient import TestClient

    from kronagent import web
    importlib.reload(web)
    web.connection_store.create(tenant_id="acme", account_id="999988887777",
                                region="us-east-1")
    yield TestClient(web.app), web
    importlib.reload(web)


def test_anonymous_cannot_enumerate_connected_tenants(connect_api) -> None:
    client, _ = connect_api
    assert client.get("/api/connections").json()["connections"] == []


def test_listing_shows_only_the_callers_own_tenants(connect_api) -> None:
    client, _ = connect_api
    assert client.get("/api/connections", headers=EVIL).json()["connections"] == []
    mine = client.get("/api/connections", headers=ACME).json()["connections"]
    assert [c["tenant_id"] for c in mine] == ["acme"]


def test_cannot_read_another_tenants_connection_detail(connect_api) -> None:
    client, _ = connect_api
    assert client.get("/api/connections/acme", headers=EVIL).status_code == 403


def test_the_external_id_template_is_not_public(connect_api) -> None:
    """The template is the one place the External ID legitimately appears — the
    secret that prevents the confused-deputy problem. It was unauthenticated."""
    client, _ = connect_api
    assert client.get("/api/connections/acme/template/contain").status_code == 403
    assert client.get("/api/connections/acme/template/contain", headers=EVIL).status_code == 403


def test_cannot_repoint_another_tenants_containment_role(connect_api) -> None:
    """Finding B. This previously returned 200 and set contain_role_arn to an
    ARN the caller controlled."""
    client, web = connect_api
    r = client.post("/api/connections/acme/role", json={
        "grant": "contain", "role_arn": "arn:aws:iam::111111111111:role/attacker",
        "operator_id": "evil-admin", "token": "evil-tok"})
    assert r.status_code == 403
    assert "attacker" not in (web.connection_store.get("acme").contain_role_arn or "")


def test_cannot_delete_another_tenants_connection(connect_api) -> None:
    """Finding C — denial of the entire product for that tenant."""
    client, web = connect_api
    r = client.request("DELETE", "/api/connections/acme",
                       json={"operator_id": "evil-admin", "token": "evil-tok"})
    assert r.status_code == 403
    assert web.connection_store.get("acme") is not None


def test_an_operator_can_still_manage_its_own_connection(connect_api) -> None:
    client, web = connect_api
    r = client.request("DELETE", "/api/connections/acme",
                       json={"operator_id": "acme-admin", "token": "acme-tok"})
    assert r.status_code == 200
    assert web.connection_store.get("acme") is None


# --------------------------------------------------------------------------- #
# The Slack webhook
# --------------------------------------------------------------------------- #

def test_slack_refuses_when_no_signing_secret_is_configured(connect_api) -> None:
    """This endpoint is internet-reachable by design, and its unauthenticated
    fallback grants the caller the admin role — so skipping signature
    verification when the secret was unset turned "anyone who can POST here"
    into "anyone can approve containment". Other surfaces may treat missing auth
    as a local single-operator posture; a public webhook cannot.
    """
    client, _ = connect_api
    r = client.post("/api/slack/interactive", content=b"payload=%7B%7D")
    assert r.status_code == 503
    assert "SIGNING_SECRET" in r.json()["detail"]


def test_verify_requires_authorization(connect_api) -> None:
    """`verify` is not a read: it performs a real STS AssumeRole into the
    customer's account, mutates the stored connection state and writes an audit
    record. It had no authorization at all, so an anonymous caller could make
    Kronagent exercise any tenant's credentials on demand — and a scoped
    operator could do it to another tenant."""
    client, _ = connect_api

    anonymous = client.post("/api/connections/acme/verify", json={"grant": "observe"})
    assert anonymous.status_code == 403

    cross_tenant = client.post("/api/connections/acme/verify", json={
        "grant": "observe", "operator_id": "evil-admin", "token": "evil-tok"})
    assert cross_tenant.status_code == 403


def test_every_tenant_scoped_endpoint_is_authorized() -> None:
    """The durable fix, rather than one more patched endpoint.

    `verify` was missed by an audit that fixed its siblings, and no test caught
    it because none covered its auth. This scans the router for any handler that
    touches a tenant without going through one of the authorization helpers, so
    the next endpoint cannot repeat it.

    If this fails for a new endpoint, route it through `tenant_scope()` (reads)
    or `_require()` (mutations) rather than relaxing the check.
    """
    import re
    from pathlib import Path

    source = Path(__file__).resolve().parent.parent / "kronagent" / "web.py"
    blocks = re.split(r'\n(?=@app\.(?:get|post|put|delete|patch)\()', source.read_text())

    guards = ("tenant_scope(", "authorize_tenant(", "_may_access_tenant(",
              "_require(", "may_access(")
    unguarded = []
    for block in blocks:
        m = re.match(r'@app\.\w+\("([^"]+)"', block)
        if not m:
            continue
        path = m.group(1)
        touches_tenant = "tenant_id" in block or "{tenant_id}" in path
        if touches_tenant and not any(g in block for g in guards):
            unguarded.append(path)

    assert not unguarded, (
        f"these endpoints resolve a tenant without authorizing it: {unguarded}"
    )
