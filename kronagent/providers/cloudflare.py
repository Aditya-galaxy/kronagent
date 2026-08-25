"""
Cloudflare Edge & WAF Security provider: normalization for Cloudflare WAF security
events and edge network IP block containment.

Normalizes Cloudflare security events (WAF, Firewall Rules, Rate Limiting)
and plans edge network block actions (`BLOCK_IP`).
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, ConfigDict

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "cloudflare"

_ACTION_SEVERITY: dict[str, float] = {
    "block": 8.0,
    "challenge": 5.0,
    "jschallenge": 4.0,
    "managed_challenge": 4.5,
    "log": 2.0,
}


class CloudflareWafEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: Optional[str] = None
    ray_id: Optional[str] = None
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    action: Optional[str] = "block"
    rule_id: Optional[str] = None
    description: Optional[str] = None
    client_ip: Optional[str] = None
    client_request_host: Optional[str] = None
    client_request_path: Optional[str] = None
    timestamp: Optional[str] = None
    tenant_id: Optional[str] = "default"


def normalize_cloudflare(raw_payload: dict[str, Any]) -> Finding:
    """Normalize a Cloudflare WAF/Firewall event dict into a provider-neutral Finding."""
    evt = CloudflareWafEvent.model_validate(raw_payload)

    event_id = evt.event_id or evt.ray_id or "cf-evt-unknown"
    zone = evt.zone_name or evt.zone_id or "global"
    action = evt.action or "block"
    severity = _ACTION_SEVERITY.get(action.lower(), 5.0)

    resources: list[ResourceRef] = []
    if evt.client_ip:
        resources.append(ResourceRef(
            kind="ip",
            id=evt.client_ip,
            attributes={"client_ip": evt.client_ip, "zone": zone}
        ))
    if evt.zone_id:
        resources.append(ResourceRef(
            kind="cloudflare.zone",
            id=evt.zone_id,
            attributes={"zone_name": zone}
        ))

    description = evt.description or f"Cloudflare WAF action '{action}' triggered on {zone} for IP {evt.client_ip or 'unknown'}"
    if evt.client_ip and evt.client_ip not in description:
        description += f" (Client IP: {evt.client_ip})"

    return Finding(
        finding_id=event_id,
        provider=PROVIDER,
        finding_type=f"cloudflare:waf_{action}",
        severity=severity,
        title=f"Cloudflare WAF Security Event: {action} on {zone}",
        description=description,
        resources=resources,
        raw_payload=raw_payload,
        tenant_id=evt.tenant_id or "default",
    )


def plan_cloudflare_actions(finding: Finding) -> list[ProposedAction]:
    """Plan candidate containment actions for Cloudflare edge security findings."""
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "ip" and r.id:
            actions.append(ProposedAction(
                provider=PROVIDER,
                action_class=ActionClass.BLOCK_IP,
                target=r.id,
                parameters={"client_ip": r.id, "zone": r.attributes.get("zone", "global")},
                rationale=f"Block attacker IP {r.id} on Cloudflare global edge network WAF firewall.",
            ))

    return actions


class CloudflareContainmentAdapter:
    """Plans Cloudflare Edge WAF IP Access Rules. Live execution is NOT implemented.

    `perform()` used to call `plan()` and return its human-readable summary
    without making any API call. The executor saw no exception and recorded
    `executed=True` with "EXECUTED - block remote IP ... on Cloudflare global
    edge network firewall" into the hash-chained audit log, so an attacker's IP
    stayed reachable while the platform certified, in signed compliance
    evidence, that it had been blocked.

    This is the same defect that was fixed in `gcp.py`, reappearing in a
    provider added afterwards, so the guard is expressed the same way here: live
    execution refuses, and `simulate=True` restores the old behaviour for tests
    only. `build_containment_adapters` leaves it at the default.

    Planning is unaffected - `plan()` is pure and honest, so dry-run still shows
    exactly the API calls a real implementation would make.
    """

    provider: str = PROVIDER

    def __init__(self, api_token: str = "", zone_id: str = "", *,
                 simulate: bool = False) -> None:
        self.api_token = api_token
        self.zone_id = zone_id
        self._simulate = simulate

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        """Pure computation of API calls, rollback, and human summary."""
        if action.action_class == ActionClass.BLOCK_IP:
            t = action.target
            zone = action.parameters.get("zone", "global")
            api_calls = [
                f"POST https://api.cloudflare.com/client/v4/zones/{zone}/firewall/access_rules/rules "
                f"{{\"mode\": \"block\", \"configuration\": {{\"target\": \"ip\", \"value\": \"{t}\"}}}}"
            ]
            rollback = f"DELETE https://api.cloudflare.com/client/v4/zones/{zone}/firewall/access_rules/rules/<rule_id_for_{t}>"
            detail = f"block remote IP {t} on Cloudflare global edge network firewall"
            return api_calls, rollback, detail
        return ([f"# no cloudflare planner for {action.action_class.value}"], "unknown", f"unhandled action {action.action_class.value}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        """Refuse rather than report a containment that did not happen.

        The executor catches this and records EXECUTION FAILED, so an operator
        can see the IP is still reachable and act on it.
        """
        calls, rollback, detail = self.plan(action)
        if not self._simulate:
            raise NotImplementedError(
                f"live Cloudflare execution for {action.action_class.value} is not "
                f"implemented - the action was NOT performed. Plan it in dry-run, or "
                f"block this address by another route."
            )
        return detail, rollback
