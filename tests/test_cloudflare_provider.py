"""
Unit tests for Cloudflare Edge & WAF Security Provider Adapter.
"""

from __future__ import annotations

import pytest

from kronagent.providers.cloudflare import (
    PROVIDER,
    normalize_cloudflare,
    CloudflareContainmentAdapter,
)
from kronagent.schemas import ActionClass


def test_cloudflare_normalization() -> None:
    raw = {
        "event_id": "cf-evt-1001",
        "zone_name": "example.com",
        "action": "block",
        "client_ip": "198.51.100.42",
        "description": "SQL injection payload detected in URI parameter",
        "tenant_id": "tenant-corp",
    }
    finding = normalize_cloudflare(raw)
    assert finding.provider == PROVIDER
    assert finding.finding_id == "cf-evt-1001"
    assert finding.severity == 8.0
    assert "198.51.100.42" in finding.description
    assert len(finding.resources) == 1
    assert finding.resources[0].kind == "ip"
    assert finding.resources[0].id == "198.51.100.42"


from kronagent.providers import plan_actions


def test_cloudflare_action_planning() -> None:
    raw = {
        "event_id": "cf-evt-1002",
        "zone_name": "example.com",
        "action": "block",
        "client_ip": "203.0.113.88",
        "tenant_id": "tenant-corp",
    }
    finding = normalize_cloudflare(raw)
    actions = plan_actions(finding)
    assert len(actions) == 1
    action = actions[0]
    assert action.action_class == ActionClass.BLOCK_IP
    assert action.target == "203.0.113.88"
    assert action.tenant_id == "tenant-corp"


from kronagent.schemas import ProposedAction


@pytest.mark.asyncio
async def test_cloudflare_containment_adapter_dry_run() -> None:
    adapter = CloudflareContainmentAdapter()
    action = ProposedAction(
        provider="cloudflare",
        action_class=ActionClass.BLOCK_IP,
        target="203.0.113.88",
        parameters={"zone": "example.com"},
        rationale="Block attacker IP on Cloudflare edge network",
    )
    api_calls, rollback, detail = adapter.plan(action)
    assert "203.0.113.88" in api_calls[0]
    assert "firewall/access_rules" in api_calls[0]
    assert "DELETE" in rollback

    # perform() is the LIVE path — dry-run never reaches it, the executor
    # short-circuits first. This previously asserted that an unconfigured
    # adapter returns success, which is exactly the defect: it made no API call
    # and the executor recorded "EXECUTED — block remote IP ..." into the
    # hash-chained audit log while the address stayed reachable.
    with pytest.raises(NotImplementedError, match="was NOT performed"):
        await adapter.perform(action)

    # The simulation remains available to tests that want it, explicitly.
    detail_res, _ = await CloudflareContainmentAdapter(simulate=True).perform(action)
    assert "block remote IP 203.0.113.88" in detail_res
