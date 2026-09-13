"""
Azure (Defender for Cloud) and in-house/on-premises providers: normalization,
planning, policy classification, and the cross-provider scope invariant.

The most important test in this file is the last one. It asserts, for EVERY
registered provider against its real sample payloads, that every planned action
targets a resource the finding actually implicates. That invariant is what makes
prompt injection in telemetry unable to redirect containment — and it is exactly
the property the GCP planner silently violated by decorating its target string
with the owning service account.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json

import pytest

from kronagent.config import Settings
from kronagent.policy import PolicyEngine
from kronagent.providers import NORMALIZERS, PLANNERS, build_containment_adapters, plan_actions
from kronagent.providers.azure import (
    AzureContainmentAdapter,
    normalize_defender,
    plan_azure_actions,
)
from kronagent.providers.onprem import (
    OnPremContainmentAdapter,
    normalize_onprem,
    plan_onprem_actions,
)
from kronagent.schemas import ActionClass
from kronagent.trajectory import legitimate_targets

from .conftest import SAMPLES_DIR


@pytest.fixture
def azure_alerts() -> list[dict]:
    return json.loads((SAMPLES_DIR / "azure_defender_alerts.json").read_text())


@pytest.fixture
def onprem_alerts() -> list[dict]:
    return json.loads((SAMPLES_DIR / "onprem_alerts.json").read_text())


# --------------------------------------------------------------------------- #
# Azure — normalization
# --------------------------------------------------------------------------- #

def test_normalize_defender_vm_and_principal(azure_alerts) -> None:
    finding = normalize_defender(azure_alerts[0])

    assert finding.provider == "azure"
    assert finding.finding_id == "kronagent-azure-credaccess-0001"
    assert finding.severity == 8.0            # "High"
    assert finding.remote_ip == "185.220.101.7"

    kinds = {r.kind for r in finding.resources}
    assert kinds == {"azure.vm", "azure.principal"}

    vm = next(r for r in finding.resources if r.kind == "azure.vm")
    assert vm.id == "vm-payments-01"
    assert vm.attributes["resource_group"] == "rg-payments"
    assert vm.attributes["subscription"] == "8f1e2c4a-5b6d-4e7f-9a0b-1c2d3e4f5a6b"

    principal = next(r for r in finding.resources if r.kind == "azure.principal")
    assert principal.id == "svc-deploy"
    assert principal.attributes["aad_object_id"] == "3f9a1b2c-7d8e-4f0a-b1c2-d3e4f5a6b7c8"
    assert principal.attributes["upn"] == "svc-deploy@contoso.onmicrosoft.com"


def test_normalize_defender_preserves_raw_payload(azure_alerts) -> None:
    """The original alert must survive normalization for the audit trail."""
    finding = normalize_defender(azure_alerts[0])
    assert finding.raw == azure_alerts[0]


def test_normalize_defender_arm_and_host_entity_do_not_duplicate_the_vm(azure_alerts) -> None:
    """Alert 0 names vm-payments-01 in BOTH resourceIdentifiers and a host
    entity. It must normalize to one resource, not two."""
    finding = normalize_defender(azure_alerts[0])
    vms = [r for r in finding.resources if r.kind == "azure.vm"]
    assert len(vms) == 1


def test_normalize_defender_severity_mapping(azure_alerts) -> None:
    assert normalize_defender(azure_alerts[1]).severity == 5.0   # Medium
    assert normalize_defender(azure_alerts[2]).severity == 2.5   # Low


def test_normalize_defender_unknown_severity_defaults_to_medium() -> None:
    finding = normalize_defender({"name": "x", "properties": {"severity": "Nonsense"}})
    assert finding.severity == 5.0


def test_normalize_defender_falls_back_to_compromised_entity() -> None:
    """When neither resourceIdentifiers nor entities resolve, compromisedEntity
    is the last-resort hint rather than producing a finding with no resources."""
    finding = normalize_defender({
        "name": "fallback-1",
        "properties": {"severity": "High", "compromisedEntity": "vm-orphan-01"},
    })
    assert [(r.kind, r.id) for r in finding.resources] == [("azure.vm", "vm-orphan-01")]


def test_normalize_defender_tolerates_empty_payload() -> None:
    finding = normalize_defender({})
    assert finding.provider == "azure"
    assert finding.finding_id == "azure-finding-unknown"
    assert finding.resources == []


# --------------------------------------------------------------------------- #
# Azure — planning
# --------------------------------------------------------------------------- #

def test_plan_azure_targets_come_from_the_finding(azure_alerts) -> None:
    finding = normalize_defender(azure_alerts[0])
    actions = plan_azure_actions(finding)

    by_class = {a.action_class: a for a in actions}
    assert by_class[ActionClass.ISOLATE_VM_NSG].target == "vm-payments-01"
    assert by_class[ActionClass.DEALLOCATE_VM].target == "vm-payments-01"
    assert by_class[ActionClass.DISABLE_ENTRA_PRINCIPAL].target == "svc-deploy"
    assert by_class[ActionClass.REVOKE_ENTRA_SESSIONS].target == "svc-deploy"
    assert by_class[ActionClass.BLOCK_IP].target == "185.220.101.7"
    assert all(a.provider == "azure" for a in actions)


def test_plan_azure_carries_resource_group_for_execution(azure_alerts) -> None:
    """resource_group is required by the real ARM calls, so it must ride along
    in parameters rather than being decoded from the target string."""
    finding = normalize_defender(azure_alerts[0])
    vm_action = next(a for a in plan_azure_actions(finding)
                     if a.action_class == ActionClass.ISOLATE_VM_NSG)
    assert vm_action.parameters["resource_group"] == "rg-payments"


def test_plan_azure_no_resources_still_blocks_the_ip() -> None:
    finding = normalize_defender({
        "name": "ip-only", "properties": {"severity": "High",
                                          "entities": [{"type": "ip", "address": "203.0.113.5"}]},
    })
    actions = plan_azure_actions(finding)
    assert [a.action_class for a in actions] == [ActionClass.BLOCK_IP]
    assert actions[0].target == "203.0.113.5"


# --------------------------------------------------------------------------- #
# On-premises — normalization
# --------------------------------------------------------------------------- #

def test_normalize_onprem_host_and_account(onprem_alerts) -> None:
    finding = normalize_onprem(onprem_alerts[0])

    assert finding.provider == "onprem"
    assert finding.finding_id == "kronagent-onprem-ssh-0001"
    assert finding.finding_type == "onprem:ssh_bruteforce_success"
    assert finding.severity == 8.0            # "high"
    assert finding.remote_ip == "185.220.101.7"

    host = next(r for r in finding.resources if r.kind == "onprem.host")
    assert host.id == "db-prod-01.corp.internal"
    assert host.attributes["ip"] == "10.20.30.41"

    account = next(r for r in finding.resources if r.kind == "onprem.account")
    assert account.id == "svc-backup"
    assert account.attributes["domain"] == "CORP"


def test_normalize_onprem_process_resource(onprem_alerts) -> None:
    finding = normalize_onprem(onprem_alerts[1])
    proc = next(r for r in finding.resources if r.kind == "onprem.process")
    assert proc.id == "44122"
    assert proc.attributes["executable"] == "/usr/bin/xmrig"
    assert proc.attributes["hostname"] == "app-web-04.corp.internal"


def test_normalize_onprem_numeric_severity_wins_over_named() -> None:
    finding = normalize_onprem({
        "alert_id": "n-1", "severity": 9.7,
        "rule": {"name": "crypto_mining", "severity": "low"},
    })
    assert finding.severity == 9.7


def test_normalize_onprem_rule_severity_used_when_no_explicit_severity() -> None:
    finding = normalize_onprem({"alert_id": "n-2", "rule": {"name": "x", "severity": "critical"}})
    assert finding.severity == 9.5


def test_normalize_onprem_rule_name_table_is_the_third_fallback(onprem_alerts) -> None:
    """Alert 2 (suricata port_scan) carries no severity at all, so the rule-name
    table supplies it."""
    finding = normalize_onprem(onprem_alerts[2])
    assert finding.severity == 3.0


def test_normalize_onprem_unknown_rule_defaults_reasonably() -> None:
    finding = normalize_onprem({"alert_id": "n-3", "rule": {"name": "brand_new_rule"}})
    assert finding.severity == 5.0
    assert finding.finding_type == "onprem:brand_new_rule"


def test_normalize_onprem_tolerates_minimal_payload() -> None:
    finding = normalize_onprem({"alert_id": "bare"})
    assert finding.finding_id == "bare"
    assert finding.resources == []
    assert finding.severity == 5.0


def test_normalize_onprem_garbage_severity_does_not_crash() -> None:
    finding = normalize_onprem({"alert_id": "g", "severity": "not-a-number"})
    assert finding.severity == 5.0


# --------------------------------------------------------------------------- #
# On-premises — planning
# --------------------------------------------------------------------------- #

def test_plan_onprem_targets_come_from_the_finding(onprem_alerts) -> None:
    finding = normalize_onprem(onprem_alerts[1])
    actions = plan_onprem_actions(finding)
    by_class = {a.action_class: a for a in actions}

    assert by_class[ActionClass.ISOLATE_HOST_NETWORK].target == "app-web-04.corp.internal"
    assert by_class[ActionClass.DISABLE_LOCAL_ACCOUNT].target == "www-data"
    assert by_class[ActionClass.KILL_PROCESS].target == "44122"
    assert by_class[ActionClass.BLOCK_IP].target == "45.133.1.90"
    assert all(a.provider == "onprem" for a in actions)


def test_plan_onprem_kill_process_carries_host_and_binary(onprem_alerts) -> None:
    finding = normalize_onprem(onprem_alerts[1])
    kill = next(a for a in plan_onprem_actions(finding)
                if a.action_class == ActionClass.KILL_PROCESS)
    assert kill.parameters["hostname"] == "app-web-04.corp.internal"
    assert kill.parameters["executable"] == "/usr/bin/xmrig"


# --------------------------------------------------------------------------- #
# Policy classification — the graduated-autonomy ceiling for the new actions
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("action_class", [
    ActionClass.DEALLOCATE_VM,
    ActionClass.REVOKE_ENTRA_SESSIONS,
    ActionClass.KILL_PROCESS,
])
async def test_destructive_new_actions_can_never_auto_execute(
    action_class, settings, allowlist_store, audit_log
) -> None:
    """Even explicitly allowlisted, a destructive action must still require a
    human. This is the structural ceiling, not a configuration default."""
    from .conftest import make_action

    await allowlist_store.add(action_class, by="test", reason="deliberately allowlisted",
                              audit=audit_log)
    policy = PolicyEngine(settings, allowlist_store)
    decision = policy.decide(make_action(action_class=action_class), severity=9.0)
    assert decision.disposition != "auto_execute"


@pytest.mark.parametrize("action_class", [
    ActionClass.ISOLATE_VM_NSG,
    ActionClass.DISABLE_ENTRA_PRINCIPAL,
    ActionClass.ISOLATE_HOST_NETWORK,
    ActionClass.DISABLE_LOCAL_ACCOUNT,
])
async def test_reversible_new_actions_are_auto_eligible_once_allowlisted(
    action_class, settings, allowlist_store, audit_log
) -> None:
    from .conftest import make_action

    await allowlist_store.add(action_class, by="test", reason="earned trust", audit=audit_log)
    policy = PolicyEngine(settings, allowlist_store)
    decision = policy.decide(make_action(action_class=action_class), severity=8.0)
    assert decision.disposition == "auto_execute"


def test_new_actions_need_the_allowlist_before_auto_executing(settings, allowlist_store) -> None:
    """Auto-eligibility alone is not enough — the earn-trust allowlist gate
    still applies to the new providers."""
    from .conftest import make_action

    policy = PolicyEngine(settings, allowlist_store)  # empty allowlist
    decision = policy.decide(
        make_action(provider="onprem", action_class=ActionClass.ISOLATE_HOST_NETWORK),
        severity=8.0,
    )
    assert decision.disposition == "requires_approval"


# --------------------------------------------------------------------------- #
# Registry + adapters
# --------------------------------------------------------------------------- #

def test_registry_includes_the_new_providers() -> None:
    assert set(NORMALIZERS) == {"aws", "azure", "cloudflare", "gcp", "kubernetes", "onprem"}
    assert set(PLANNERS) == {"aws", "azure", "cloudflare", "gcp", "kubernetes", "onprem"}


def test_build_containment_adapters_registers_the_new_providers() -> None:
    adapters = build_containment_adapters(Settings())
    assert isinstance(adapters["azure"], AzureContainmentAdapter)
    assert isinstance(adapters["onprem"], OnPremContainmentAdapter)


def test_plan_actions_dispatches_to_the_new_providers(azure_alerts, onprem_alerts) -> None:
    assert all(a.provider == "azure" for a in plan_actions(normalize_defender(azure_alerts[0])))
    assert all(a.provider == "onprem" for a in plan_actions(normalize_onprem(onprem_alerts[0])))


def test_azure_adapter_plan_never_builds_a_client() -> None:
    """Dry-run must need no credentials: plan() is pure."""
    from .conftest import make_action

    adapter = AzureContainmentAdapter(subscription_id="sub", quarantine_nsg_id="nsg-fake")
    adapter._credential = lambda: pytest.fail("plan() must not construct a credential")
    adapter._compute_client = lambda: pytest.fail("plan() must not construct a compute client")
    adapter._network_client = lambda: pytest.fail("plan() must not construct a network client")

    for ac in [ActionClass.ISOLATE_VM_NSG, ActionClass.DEALLOCATE_VM,
               ActionClass.DISABLE_ENTRA_PRINCIPAL, ActionClass.REVOKE_ENTRA_SESSIONS,
               ActionClass.BLOCK_IP]:
        calls, rollback, detail = adapter.plan(
            make_action(provider="azure", action_class=ac, parameters={"resource_group": "rg"})
        )
        assert calls and rollback and detail


def test_onprem_adapter_plan_needs_no_control_plane() -> None:
    from .conftest import make_action

    adapter = OnPremContainmentAdapter()  # nothing configured
    for ac in [ActionClass.ISOLATE_HOST_NETWORK, ActionClass.DISABLE_LOCAL_ACCOUNT,
               ActionClass.KILL_PROCESS, ActionClass.BLOCK_IP]:
        calls, rollback, detail = adapter.plan(make_action(provider="onprem", action_class=ac))
        assert calls and rollback and detail
        # Unconfigured values surface as honest placeholders, never as a
        # plausible-looking but wrong endpoint.
        assert "unset" in " ".join(calls) or "http" in " ".join(calls)


async def test_onprem_perform_without_a_control_plane_fails_loudly() -> None:
    """An unconfigured on-prem deployment must not silently no-op: the executor
    surfaces this as EXECUTION FAILED rather than reporting success."""
    from .conftest import make_action

    adapter = OnPremContainmentAdapter()
    with pytest.raises(RuntimeError, match="CONTROL_PLANE_URL is not configured"):
        await adapter.perform(
            make_action(provider="onprem", action_class=ActionClass.BLOCK_IP, target="1.2.3.4")
        )


async def test_onprem_isolate_without_a_vlan_fails_loudly() -> None:
    from .conftest import make_action

    adapter = OnPremContainmentAdapter(control_plane_url="https://nac.corp.internal")
    with pytest.raises(RuntimeError, match="QUARANTINE_VLAN is not configured"):
        await adapter.perform(
            make_action(provider="onprem", action_class=ActionClass.ISOLATE_HOST_NETWORK,
                        target="host-1")
        )


# --------------------------------------------------------------------------- #
# The cross-provider invariant.
#
# This is the regression test for the class of bug the GCP planner had: a
# planner that decorates or reformats its target produces an action the
# trajectory guard must reject as an out-of-scope redirection, silently
# breaking that containment path in production.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("provider,sample_file", [
    ("aws", "guardduty_findings.json"),
    ("azure", "azure_defender_alerts.json"),
    ("gcp", "gcp_scc_findings.json"),
    ("kubernetes", "k8s_audit_events.json"),
    ("onprem", "onprem_alerts.json"),
])
def test_every_planned_action_targets_a_resource_the_finding_implicates(
    provider, sample_file
) -> None:
    path = SAMPLES_DIR / sample_file
    if not path.exists():
        pytest.skip(f"no sample payloads for {provider}")

    payloads = json.loads(path.read_text())
    if isinstance(payloads, dict):
        payloads = [payloads]

    checked = 0
    for payload in payloads:
        finding = NORMALIZERS[provider](payload)
        allowed = legitimate_targets(finding)
        for action in plan_actions(finding):
            assert action.target in allowed, (
                f"{provider}: {action.action_class.value} targets {action.target!r}, "
                f"which is not one of the finding's own resources {sorted(allowed)}. "
                f"The trajectory guard would block this action in production."
            )
            checked += 1

    assert checked > 0, f"{provider} sample produced no actions to check"


# --------------------------------------------------------------------------- #
# Control-plane URL scheme validation
#
# urllib honours whatever scheme it is given. An on-prem control plane
# configured as file:///etc/shadow would be opened as a local file and its
# contents treated as a containment response — a config-to-file-read primitive
# inside the component holding the most privilege.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_url", [
    "file:///etc/shadow",
    "file://localhost/etc/passwd",
    "ftp://internal.example/x",
    "gopher://internal.example/x",
    "data:text/plain,contained",
    "/etc/passwd",                 # no scheme at all
])
def test_non_http_control_plane_is_rejected_at_construction(bad_url) -> None:
    with pytest.raises(ValueError, match="must use http or https"):
        OnPremContainmentAdapter(control_plane_url=bad_url)


@pytest.mark.parametrize("good_url,expected", [
    ("https://nac.corp.internal", "https://nac.corp.internal"),
    ("http://10.0.0.5:8443/api/", "http://10.0.0.5:8443/api"),
    ("HTTPS://NAC.CORP.INTERNAL", "HTTPS://NAC.CORP.INTERNAL"),   # scheme compare is case-insensitive
])
def test_http_control_plane_is_accepted(good_url, expected) -> None:
    assert OnPremContainmentAdapter(control_plane_url=good_url)._url == expected


def test_unset_control_plane_still_constructs() -> None:
    """Unset is legal — plan() must still describe what it *would* do, and
    perform() refuses separately with its own message. Rejecting empty here
    would break dry-run planning for anyone who has not wired a control plane."""
    assert OnPremContainmentAdapter(control_plane_url="")._url == ""
