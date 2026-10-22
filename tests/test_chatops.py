"""
Unit and integration tests for the Kronagent ChatOps Slack integration.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import time
import os
import tempfile
import urllib.parse
import pytest

from fastapi.testclient import TestClient

from kronagent.web import app
from kronagent.chatops import verify_slack_signature, ChatOpsNotifier
from kronagent.approvals import ApprovalStore, ApprovalRequest
from kronagent.allowlist import AllowlistStore
from kronagent.audit import AuditLog
from kronagent.schemas import ActionClass


@pytest.fixture
def test_env():
    """Setup temporary files and configure Settings to test webhook execution."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_approval_path = os.path.join(temp_dir, "test_approvals.json")
        temp_allowlist_path = os.path.join(temp_dir, "test_allowlist.json")
        temp_audit_path = os.path.join(temp_dir, "test_audit.jsonl")
        temp_registry_path = os.path.join(temp_dir, "test_registry.json")

        from kronagent.identity import hash_token
        registry_data = {
            "alice": {
                "display_name": "Alice Admin",
                "roles": ["admin"],
                "token_sha256": hash_token("secret"),
                "active": True
            }
        }
        with open(temp_registry_path, "w", encoding="utf-8") as f:
            json.dump(registry_data, f)

        from kronagent import web
        from kronagent.config import Settings

        test_settings = Settings(
            dry_run=True,
            approval_store_path=temp_approval_path,
            allowlist_store_path=temp_allowlist_path,
            audit_log_path=temp_audit_path,
            operator_registry_path=temp_registry_path,
            slack_signing_secret="test_secret",
            slack_user_mapping={"U12345": "alice"}
        )

        orig_settings = web.settings
        orig_approval = web.approval_store
        orig_allowlist = web.allowlist_store
        orig_audit = web.audit_log

        web.settings = test_settings
        web.approval_store = ApprovalStore(temp_approval_path)
        web.allowlist_store = AllowlistStore(temp_allowlist_path)
        web.audit_log = AuditLog(temp_audit_path)

        client = TestClient(app)
        try:
            yield client, web.approval_store, web.audit_log, test_settings
        finally:
            web.settings = orig_settings
            web.approval_store = orig_approval
            web.allowlist_store = orig_allowlist
            web.audit_log = orig_audit


def test_signature_verification() -> None:
    secret = "my_secret"
    body = b"payload=%7B%22type%22%3A%22block_actions%22%7D"
    timestamp = str(int(time.time()))
    
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body
    computed = "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    assert verify_slack_signature(secret, body, timestamp, computed) is True
    assert verify_slack_signature(secret, body, timestamp, "invalid") is False
    assert verify_slack_signature("", body, timestamp, computed) is False


def test_build_blocks_pending() -> None:
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
    blocks = ChatOpsNotifier.build_slack_blocks(req)
    assert len(blocks) >= 3
    # Check that it contains the Actions block with buttons
    actions = [b for b in blocks if b.get("type") == "actions"]
    assert len(actions) == 1
    elements = actions[0]["elements"]
    assert elements[0]["action_id"] == "approve_action"
    assert elements[1]["action_id"] == "deny_action"


def test_build_blocks_resolved() -> None:
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
    blocks = ChatOpsNotifier.build_slack_blocks(req, "Approved by @alice")
    actions = [b for b in blocks if b.get("type") == "actions"]
    assert len(actions) == 0
    verdict = [b for b in blocks if b.get("type") == "section" and "Verdict" in b.get("text", {}).get("text", "")]
    assert len(verdict) == 1


def test_webhook_invalid_signature(test_env) -> None:
    client, _, _, _ = test_env
    res = client.post(
        "/api/slack/interactive",
        content="payload=%7B%7D",
        headers={
            "X-Slack-Signature": "invalid",
            "X-Slack-Request-Timestamp": "12345678"
        }
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_webhook_approve_success(test_env) -> None:
    client, store, _, settings = test_env

    # 1. Create a pending request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=8.2,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)

    # 2. Build mock interactive payload
    payload = {
        "type": "block_actions",
        "user": {
            "id": "U12345",
            "username": "alice_slack"
        },
        "actions": [
            {
                "action_id": "approve_action",
                "value": req.request_id
            }
        ]
    }

    body = f"payload={urllib.parse.quote(json.dumps(payload))}"
    timestamp = str(int(time.time()))
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body.encode("utf-8")
    signature = "v0=" + hmac.new(settings.slack_signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    # 3. Post to the webhook
    res = client.post(
        "/api/slack/interactive",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Slack-Signature": signature,
            "X-Slack-Request-Timestamp": timestamp
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("replace_original") is True
    assert "Approved" in data.get("text")

    # Verify request status is updated in store
    updated = store.get(req.request_id)
    assert updated.status in {"approved", "executed"}
    assert updated.decided_by == "alice"


@pytest.mark.asyncio
async def test_webhook_deny_success(test_env) -> None:
    client, store, _, settings = test_env

    # 1. Create a pending request
    req = ApprovalRequest(
        finding_id="f-1",
        finding_type="aws:iam_abuse",
        severity=8.2,
        action_class=ActionClass.DISABLE_ACCESS_KEY,
        target="AKIA123",
        rationale="compromised keys",
        policy_reason="approval required",
        reversible=True,
        blast_radius="single_resource"
    )
    store.add(req)

    # 2. Build mock interactive payload
    payload = {
        "type": "block_actions",
        "user": {
            "id": "U12345",
            "username": "alice_slack"
        },
        "actions": [
            {
                "action_id": "deny_action",
                "value": req.request_id
            }
        ]
    }

    body = f"payload={urllib.parse.quote(json.dumps(payload))}"
    timestamp = str(int(time.time()))
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body.encode("utf-8")
    signature = "v0=" + hmac.new(settings.slack_signing_secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()

    # 3. Post to the webhook
    res = client.post(
        "/api/slack/interactive",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Slack-Signature": signature,
            "X-Slack-Request-Timestamp": timestamp
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("replace_original") is True
    assert "Rejected" in data.get("text")

    # Verify request status in store
    updated = store.get(req.request_id)
    assert updated.status == "denied"
    assert updated.decided_by == "alice"


# --------------------------------------------------------------------------- #
# Allowlist expiry warnings — deliberately non-interactive
# --------------------------------------------------------------------------- #

def _expiring_entry(**kwargs):
    from kronagent.allowlist import AllowlistEntry
    base = {
        "action_class": "disable_access_key", "promoted_by": "alice", "owner": "dana",
        "reason": "30 days incident-free", "promoted_at": "2026-05-01T00:00:00+00:00",
        "expires_at": "2026-08-11T00:00:00+00:00",
    }
    return AllowlistEntry(**{**base, **kwargs})


def _card_text(blocks) -> str:
    parts = []
    for b in blocks:
        if "text" in b:
            parts.append(b["text"].get("text", ""))
        for f in b.get("fields", []):
            parts.append(f.get("text", ""))
    return "\n".join(parts)


def test_expiry_warning_card_carries_the_renewal_context() -> None:
    from kronagent.config import Settings
    settings = Settings(slack_user_mapping={"U12345": "dana"})
    text = _card_text(ChatOpsNotifier.build_expiry_warning_blocks(
        settings, _expiring_entry(), remaining="9d"))

    assert "lapses in *9d*" in text
    assert "<@U12345>" in text                    # owner @-mentioned
    assert "30 days incident-free" in text        # why it was promoted
    assert "promote.py add disable_access_key" in text
    assert "never* — it has authorized nothing" in text


def test_expiry_warning_card_says_doing_nothing_is_safe() -> None:
    """The message has to reinforce fail-closed, or an owner reads a countdown
    and assumes something bad happens if they ignore it."""
    from kronagent.config import Settings
    text = _card_text(ChatOpsNotifier.build_expiry_warning_blocks(
        Settings(), _expiring_entry(), remaining="3d"))
    assert "do nothing" in text
    assert "requiring human approval" in text
    assert "Silence is the safe answer" in text


def test_expiry_warning_card_has_no_buttons() -> None:
    """Renewal needs a fresh, audited reason for why the class still deserves
    autonomy. A one-click renew button is exactly how that gets hollowed out."""
    from kronagent.config import Settings
    blocks = ChatOpsNotifier.build_expiry_warning_blocks(
        Settings(), _expiring_entry(), remaining="9d")
    assert [b for b in blocks if b.get("type") == "actions"] == []


def test_expiry_warning_falls_back_to_the_plain_owner_id() -> None:
    from kronagent.config import Settings
    text = _card_text(ChatOpsNotifier.build_expiry_warning_blocks(
        Settings(slack_user_mapping={"U999": "someone-else"}), _expiring_entry(), remaining="9d"))
    assert "`dana`" in text


def test_expiry_warning_send_is_a_noop_without_slack_configured() -> None:
    """No token, no post attempt — and False, so the audit record says plainly
    that nobody was told."""
    from kronagent.config import Settings
    assert ChatOpsNotifier.send_expiry_warning(
        Settings(), _expiring_entry(), remaining="9d") is False


def test_a_stale_signature_is_refused() -> None:
    """A correctly signed request older than five minutes is a replay."""
    secret, body = "my_secret", b"payload=x"
    timestamp = "1700000000"
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + body
    computed = "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    assert verify_slack_signature(secret, body, timestamp, computed, now=1700000000 + 299) is True
    assert verify_slack_signature(secret, body, timestamp, computed, now=1700000000 + 301) is False
    assert verify_slack_signature(secret, body, timestamp, computed, now=1700000000 - 301) is False
    assert verify_slack_signature(secret, body, "not-a-number", computed) is False


def test_respond_only_posts_to_slack_hooks(monkeypatch) -> None:
    """The reply URL comes from the payload; it must never point Kronagent elsewhere."""
    from kronagent import chatops
    sent: list[str] = []

    class _Resp:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(chatops.urllib.request, "urlopen",
                        lambda req, timeout: sent.append(req.full_url) or _Resp())
    assert chatops.respond("https://hooks.slack.com/actions/T1/1/abc", {"text": "ok"}) is True
    for bad in ("http://hooks.slack.com/actions/x", "https://hooks.slack.com.evil.example/x",
                "https://169.254.169.254/latest/meta-data", "file:///etc/passwd", ""):
        assert chatops.respond(bad, {"text": "x"}) is False
    assert sent == ["https://hooks.slack.com/actions/T1/1/abc"]
