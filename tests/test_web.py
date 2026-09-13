"""
Unit and integration tests for the Kronagent Analyst Console Web Server.
"""

from __future__ import annotations

import json
from pathlib import Path
import os
import tempfile
import pytest

from fastapi.testclient import TestClient

from kronagent.web import app
from kronagent.approvals import ApprovalStore, ApprovalRequest
from kronagent.allowlist import AllowlistStore
from kronagent.audit import AuditLog
from kronagent.schemas import ActionClass


@pytest.fixture
def test_env():
    """Setup temporary files for the store paths to avoid modifying local workspace state."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_approval_path = os.path.join(temp_dir, "test_approvals.json")
        temp_allowlist_path = os.path.join(temp_dir, "test_allowlist.json")
        temp_audit_path = os.path.join(temp_dir, "test_audit.jsonl")
        temp_registry_path = os.path.join(temp_dir, "test_registry.json")
        
        # Write dummy registry
        from kronagent.identity import hash_token
        registry_data = {
            "alice": {
                "display_name": "Alice Admin",
                "roles": ["admin"],
                "token_sha256": hash_token("secret"),
                "active": True
            },
            "bob": {
                "display_name": "Bob Viewer",
                "roles": ["viewer"],
                "token_sha256": hash_token("password"),
                "active": True
            },
            # Owners who never sign in during these tests but must exist:
            # an allowlist entry can only be held by someone who could renew it.
            "dana": {"display_name": "Dana Owner", "roles": ["admin"], "active": True},
            "erin": {"display_name": "Erin Owner", "roles": ["admin"], "active": True},
        }
        with open(temp_registry_path, "w", encoding="utf-8") as f:
            json.dump(registry_data, f)

        # Import modules to override
        from kronagent import web
        from kronagent.config import Settings
        
        test_settings = Settings(
            dry_run=True,
            approval_store_path=temp_approval_path,
            allowlist_store_path=temp_allowlist_path,
            audit_log_path=temp_audit_path,
            operator_registry_path=temp_registry_path
        )
        
        # Backup original web components
        orig_settings = web.settings
        orig_approval = web.approval_store
        orig_allowlist = web.allowlist_store
        orig_audit = web.audit_log
        
        # Override web components
        web.settings = test_settings
        web.approval_store = ApprovalStore(temp_approval_path)
        web.allowlist_store = AllowlistStore(temp_allowlist_path)
        web.audit_log = AuditLog(temp_audit_path)
        
        client = TestClient(app)
        try:
            yield client, web.approval_store, web.allowlist_store, web.audit_log
        finally:
            # Restore original web components
            web.settings = orig_settings
            web.approval_store = orig_approval
            web.allowlist_store = orig_allowlist
            web.audit_log = orig_audit


def test_read_index(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/")
    assert res.status_code == 200
    assert "Kronagent Analyst Console" in res.text


def test_get_status(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "dry_run" in data
    assert "kill_switch" in data
    assert "integrity_verified" in data


def test_get_approvals_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/approvals")
    assert res.status_code == 200
    assert res.json() == []


def test_get_allowlist_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/allowlist")
    assert res.status_code == 200
    assert res.json() == []


def test_get_metrics_empty(test_env) -> None:
    client, _, _, _ = test_env
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["total_findings"] == 0
    assert data["total_pending"] == 0


@pytest.mark.asyncio
async def test_execute_approval_action_unauthorized(test_env) -> None:
    client, store, _, _ = test_env
    
    # 1. Add a pending approval request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=7.5,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)
    
    # 2. Deny action with invalid credentials (bob is only a viewer, lacks approve)
    res = client.post(
        f"/api/approvals/{req.request_id}/action",
        json={
            "action": "deny",
            "operator_id": "bob",
            "token": "password",
            "reason": "compromised keys"
        }
    )
    assert res.status_code == 403
    assert "lacks the 'approve' permission" in res.json()["detail"]


@pytest.mark.asyncio
async def test_execute_approval_action_success(test_env) -> None:
    client, store, _, audit = test_env
    
    # 1. Add a pending approval request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=7.5,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)
    
    # 2. Approve action with valid credentials (alice is admin)
    res = client.post(
        f"/api/approvals/{req.request_id}/action",
        json={
            "action": "approve",
            "operator_id": "alice",
            "token": "secret",
            "reason": "approved for incident mitigation"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in {"approved", "executed"}
    
    # Verify request status in database
    updated_req = store.get(req.request_id)
    assert updated_req is not None
    assert updated_req.status in {"approved", "executed"}
    assert updated_req.decided_by == "alice"


def test_promote_allowlist_success(test_env) -> None:
    client, _, allowlist, _ = test_env
    
    # Promote action class with valid credentials (alice is admin)
    res = client.post(
        "/api/allowlist/promote",
        json={
            "action_class": "isolate_pod",
            "operator_id": "alice",
            "token": "secret",
            "reason": "promote isolate_pod for fast mitigation"
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    # Verify allowlist state in database
    assert "isolate_pod" in [entry.action_class for entry in allowlist.list()]


def test_promote_allowlist_with_ttl(test_env) -> None:
    client, _, allowlist, _ = test_env

    res = client.post(
        "/api/allowlist/promote",
        json={
            "action_class": "isolate_pod",
            "operator_id": "alice",
            "token": "secret",
            "reason": "90-day trial of autonomy",
            "expires_in": "90d",
        }
    )
    assert res.status_code == 200
    assert res.json()["expires_at"] is not None
    assert allowlist.list()[0].expires_at == res.json()["expires_at"]


def test_promote_allowlist_rejects_an_unparseable_ttl(test_env) -> None:
    client, _, allowlist, _ = test_env
    res = client.post(
        "/api/allowlist/promote",
        json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
              "reason": "r", "expires_in": "90"}
    )
    assert res.status_code == 400
    assert allowlist.list() == []  # nothing promoted on a bad TTL


def test_promote_allowlist_with_an_owner(test_env) -> None:
    client, _, allowlist, _ = test_env
    res = client.post(
        "/api/allowlist/promote",
        json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
              "reason": "r", "owner": "dana"}
    )
    assert res.status_code == 200
    assert res.json()["owner"] == "dana"
    entry = allowlist.list()[0]
    assert (entry.owner, entry.promoted_by) == ("dana", "alice")


def test_reassign_allowlist_owner(test_env) -> None:
    client, _, allowlist, _ = test_env
    client.post("/api/allowlist/promote",
                json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
                      "reason": "30 days incident-free", "owner": "dana"})

    res = client.post(
        "/api/allowlist/reassign",
        json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
              "reason": "dana moved to platform", "owner": "erin"}
    )
    assert res.status_code == 200
    entry = allowlist.list()[0]
    assert entry.owner == "erin"
    assert entry.promoted_by == "alice"            # history untouched
    assert entry.reason == "30 days incident-free"


def test_promote_refuses_an_owner_who_could_not_renew_the_entry(test_env) -> None:
    """bob is a viewer and mallory is not in the registry. Neither could ever
    say yes again, so neither can be made accountable for saying it."""
    client, _, allowlist, _ = test_env
    for owner in ("bob", "mallory"):
        res = client.post(
            "/api/allowlist/promote",
            json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
                  "reason": "r", "owner": owner},
        )
        assert res.status_code == 400, owner
        assert owner in res.json()["detail"]
    assert allowlist.list() == []


def test_reassign_refuses_an_owner_not_in_standing(test_env) -> None:
    client, _, allowlist, _ = test_env
    client.post("/api/allowlist/promote",
                json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
                      "reason": "r", "owner": "dana"})
    res = client.post(
        "/api/allowlist/reassign",
        json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
              "reason": "r", "owner": "mallory"},
    )
    assert res.status_code == 400
    assert allowlist.list()[0].owner == "dana"


def test_allowlist_endpoints_report_a_departed_owner(test_env) -> None:
    """The console must not list autonomy the gate already refuses, and the
    review must say why rather than show the entry as healthy."""
    client, _, allowlist, _ = test_env
    client.post("/api/allowlist/promote",
                json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
                      "reason": "r", "owner": "dana"})
    assert client.get("/api/allowlist").json() == ["isolate_pod"]
    from kronagent import web
    registry = json.loads(Path(web.settings.operator_registry_path).read_text())
    registry["dana"]["active"] = False
    Path(web.settings.operator_registry_path).write_text(json.dumps(registry))

    assert client.get("/api/allowlist").json() == []
    review = client.get("/api/allowlist/review").json()[0]
    assert review["owner_standing_checked"] is True
    assert "deactivated" in review["owner_vacancy"]


def test_reassign_allowlist_owner_requires_promote_permission(test_env) -> None:
    client, _, allowlist, _ = test_env
    client.post("/api/allowlist/promote",
                json={"action_class": "isolate_pod", "operator_id": "alice", "token": "secret",
                      "reason": "r", "owner": "dana"})

    # bob is a viewer
    res = client.post(
        "/api/allowlist/reassign",
        json={"action_class": "isolate_pod", "operator_id": "bob", "token": "password",
              "reason": "r", "owner": "bob"}
    )
    assert res.status_code == 403
    assert allowlist.list()[0].owner == "dana"


def test_allowlist_endpoint_omits_lapsed_entries(test_env) -> None:
    """A console that still listed a lapsed entry as promoted would be
    describing autonomy the policy engine has already withdrawn."""
    client, _, allowlist, _ = test_env
    allowlist._write_all({"isolate_pod": {
        "action_class": "isolate_pod", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00", "expires_at": "2026-02-01T00:00:00+00:00",
    }})

    assert client.get("/api/allowlist").json() == []

    review = client.get("/api/allowlist/review").json()
    assert len(review) == 1
    assert review[0]["action_class"] == "isolate_pod"
    assert review[0]["expired"] is True
    assert review[0]["never_fired"] is True
    assert review[0]["reason"] == "r"


@pytest.mark.asyncio
async def test_demote_allowlist_success(test_env) -> None:
    client, _, allowlist, audit = test_env
    
    await allowlist.add(
        ActionClass.ISOLATE_POD,
        by="alice",
        reason="test setup",
        audit=audit
    )
    
    # Demote action class with valid credentials (alice is admin)
    res = client.post(
        "/api/allowlist/demote",
        json={
            "action_class": "isolate_pod",
            "operator_id": "alice",
            "token": "secret",
            "reason": "demote isolate_pod"
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    
    # Verify allowlist state in database
    assert "isolate_pod" not in [entry.action_class for entry in allowlist.list()]


# --------------------------------------------------------------------------- #
# Console wiring — the dashboard shipped for months as a static mockup because
# index.html never referenced app.js. Nothing failed; it just did nothing.
# --------------------------------------------------------------------------- #

def test_index_loads_the_client_application() -> None:
    """Without this script tag the console renders placeholder zeros and empty
    tables forever: no fetches, no buttons, no governance surface at all."""
    import os as _os
    from kronagent import web as _web
    index = _os.path.join(_web.STATIC_DIR, "index.html")
    with open(index, "r", encoding="utf-8") as fh:
        html = fh.read()
    assert '<script src="/static/app.js"></script>' in html


def test_review_endpoint_serves_the_policy_engines_own_classification(test_env) -> None:
    """The console used to derive blast radius from the action-class name and
    got it wrong — it showed revoke_role_sessions as account-wide when the
    policy table calls it single-resource but destructive. Serving the real
    classification is the difference between the console describing the safety
    ceiling and guessing at it."""
    client, _, allowlist, _ = test_env
    allowlist._write_all({
        "revoke_role_sessions": {
            "action_class": "revoke_role_sessions", "promoted_by": "alice", "reason": "r",
            "promoted_at": "2026-05-01T00:00:00+00:00", "owner": "dana",
        },
        "block_ip": {
            "action_class": "block_ip", "promoted_by": "alice", "reason": "r",
            "promoted_at": "2026-05-01T00:00:00+00:00", "owner": "erin",
        },
    })

    by_class = {e["action_class"]: e for e in client.get("/api/allowlist/review").json()}

    # Destructive-but-single-resource: the console must show it can never
    # auto-execute, no matter that it sits on the allowlist.
    assert by_class["revoke_role_sessions"]["blast_radius"] == "single_resource"
    assert by_class["revoke_role_sessions"]["auto_eligible"] is False
    assert by_class["revoke_role_sessions"]["known_action_class"] is True

    assert by_class["block_ip"]["blast_radius"] == "single_resource"
    assert by_class["block_ip"]["auto_eligible"] is True
    assert by_class["block_ip"]["reversible"] is True


def test_review_endpoint_survives_an_unknown_action_class(test_env) -> None:
    """A renamed or removed action leaves an orphan entry. It grants nothing,
    and the console has to say so rather than render blanks."""
    client, _, allowlist, _ = test_env
    allowlist._write_all({"retired_action": {
        "action_class": "retired_action", "promoted_by": "alice", "reason": "r",
        "promoted_at": "2026-05-01T00:00:00+00:00", "owner": "dana",
    }})

    entry = client.get("/api/allowlist/review").json()[0]
    assert entry["known_action_class"] is False
    assert entry["auto_eligible"] is False
    assert entry["blast_radius"] is None


def _static(name: str) -> str:
    import os as _os
    from kronagent import web as _web
    with open(_os.path.join(_web.STATIC_DIR, name), "r", encoding="utf-8") as fh:
        return fh.read()


def test_every_nav_item_has_a_label_element() -> None:
    """The page title used to be the nav label's second whitespace-separated
    token, which truncated three of the four tabs to "Approval", "Audit" and
    "Allowlist". It reads a dedicated label element now, so the label has to
    exist on every nav item."""
    html = _static("index.html")
    assert html.count('class="nav-item"') + html.count('class="nav-item active"') == \
        html.count('class="nav-label"')


def test_no_literal_markdown_in_rendered_strings() -> None:
    """Nothing parses markdown in this console — template strings go straight
    into innerHTML. `by **alice**` rendered with the asterisks visible."""
    js = _static("app.js")

    def _is_comment(line: str) -> bool:
        # `//` was already excluded; a JSDoc block is equally never rendered,
        # and `/**` trips the `**` check by construction. Excluding comments
        # does not weaken this: a real offender is a template string, and
        # template strings are not comments.
        stripped = line.strip()
        return (stripped.startswith("//") or stripped.startswith("/*")
                or stripped.startswith("*") or "//" in line)

    rendered = [ln for ln in js.splitlines()
                if ("stageDesc =" in ln or "<p>" in ln) and not _is_comment(ln)]
    offenders = [ln.strip() for ln in rendered if "**" in ln]
    assert offenders == [], f"literal markdown reaches innerHTML: {offenders}"


def test_promote_panel_does_not_show_raw_backticks() -> None:
    html = _static("index.html")
    assert "requires `PROMOTE`" not in html
    assert "<code>PROMOTE</code>" in html


def test_siem_export_endpoint(test_env) -> None:
    client, _, _, audit = test_env
    # Record a test audit record
    from kronagent.schemas import AuditRecord
    import asyncio
    asyncio.run(audit.record(AuditRecord(
        finding_id="f-siem-1",
        stage="triage",
        payload={"threat": True, "severity": 8.0, "reason": "High severity exfil"}
    )))

    res = client.get("/api/export/siem")
    assert res.status_code == 200
    data = res.json()
    assert data["verified"] is True
    assert data["total_events"] >= 1
    assert any(e.get("finding_id") == "f-siem-1" or "f-siem-1" in str(e) for e in data["events"])





def _stamp(r: ApprovalRequest, *, status: str, by: str, secs: int, n: int) -> ApprovalRequest:
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 3, 1, 12, tzinfo=timezone.utc)
    r.status = status
    r.decided_by = by
    r.created_at = (base + timedelta(seconds=n)).isoformat()
    r.decided_at = (base + timedelta(seconds=n + secs)).isoformat()
    return r


def _approval(n: int) -> ApprovalRequest:
    return ApprovalRequest(
        finding_id=f"f-{n}",
        finding_type="Backdoor:EC2/C&CActivity.B",
        severity=8.0,
        action_class=ActionClass.TERMINATE_INSTANCE,
        target="i-1",
        rationale="test",
        policy_reason="requires approval",
        reversible=False,
        blast_radius="single_resource",
    )


def test_oversight_endpoint_reports_a_healthy_queue(test_env) -> None:
    client, store, _, _ = test_env
    for i in range(15):
        store.add(_stamp(_approval(i), status="approved", by="alice", secs=600, n=i))
    for i in range(15, 25):
        store.add(_stamp(_approval(i), status="denied", by="bob", secs=600, n=i))

    body = client.get("/api/oversight").json()
    assert body["decided"] == 25
    assert body["deny_rate"] == 0.4
    assert body["median_seconds_to_decide"] == 600.0
    assert body["healthy"] is True
    assert body["warnings"] == []


def test_oversight_endpoint_exposes_a_degrading_control(test_env) -> None:
    """The console must be able to show that its own oversight has decayed —
    the numbers are useless if only a CLI nobody runs can see them."""
    client, store, _, _ = test_env
    for i in range(25):
        store.add(_stamp(_approval(i), status="approved", by="alice", secs=3, n=i))

    body = client.get("/api/oversight").json()
    assert body["healthy"] is False
    assert body["deny_rate"] == 0.0
    assert body["hasty_consequential"] == 25
    assert any("DENY RATE" in w for w in body["warnings"])
    assert {s["operator_id"] for s in body["by_operator"]} == {"alice"}
