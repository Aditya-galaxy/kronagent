"""
Provider normalization + planning, for both AWS and Kubernetes, plus the
registry that dispatches between them.

The single most important property tested here: every action target comes
from the normalized finding's resources, never invented -- this is what makes
prompt injection in telemetry unable to redirect containment onto an
attacker-chosen resource.
"""

from __future__ import annotations

import pytest

from kronagent.providers import NORMALIZERS, PLANNERS, build_containment_adapters, plan_actions
from kronagent.providers.aws import AwsContainmentAdapter, normalize_guardduty, plan_aws_actions
from kronagent.providers.k8s import K8sContainmentAdapter, normalize_k8s, plan_k8s_actions
from kronagent.schemas import ActionClass
from kronagent.config import Settings

# --------------------------------------------------------------------------- #
# AWS / GuardDuty
# --------------------------------------------------------------------------- #

def test_normalize_guardduty_access_key(guardduty_findings) -> None:
    raw = guardduty_findings[0]  # credential exfiltration finding
    finding = normalize_guardduty(raw)

    assert finding.provider == "aws"
    assert finding.finding_id == "kronagent-finding-cred-exfil-0001"
    assert finding.severity == 8.0
    assert finding.remote_ip == "185.220.101.7"
    # Instance credentials are temporary (ASIA) and belong to a role, not a user.
    kinds = {r.kind for r in finding.resources}
    assert kinds == {"aws.sts.temporary_credentials", "aws.iam.role"}
    key_res = next(r for r in finding.resources if r.kind == "aws.sts.temporary_credentials")
    assert key_res.id == "ASIAEXAMPLECREDEXFIL"
    assert key_res.attributes["user_name"] == "svc-backup"
    assert next(r for r in finding.resources if r.kind == "aws.iam.role").id == "svc-backup"


def test_normalize_guardduty_instance(guardduty_findings) -> None:
    raw = guardduty_findings[1]  # cryptomining finding
    finding = normalize_guardduty(raw)
    assert finding.resources[0].kind == "aws.ec2.instance"
    assert finding.resources[0].id == "i-0a1b2c3d4e5f60789"


def test_stolen_role_credentials_revoke_the_roles_sessions(guardduty_findings) -> None:
    """A temporary key cannot be deactivated and a role is not a user: the
    containment that works is denying every session issued before now."""
    finding = normalize_guardduty(guardduty_findings[0])
    actions = plan_aws_actions(finding)
    classes = {a.action_class for a in actions}

    assert ActionClass.DISABLE_ACCESS_KEY not in classes
    assert ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL not in classes
    revoke = [a for a in actions if a.action_class == ActionClass.REVOKE_ROLE_SESSIONS]
    assert [a.target for a in revoke] == ["svc-backup"]   # from the finding, not invented
    assert revoke[0].provider == "aws"

    block_actions = [a for a in actions if a.action_class == ActionClass.BLOCK_IP]
    assert block_actions[0].target == "185.220.101.7"


def _key_finding(key: str, user: str, user_type: str | None) -> dict:
    details = {"AccessKeyId": key, "UserName": user}
    if user_type is not None:
        details["UserType"] = user_type
    return {"Id": "f-key", "Type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", "Severity": 8.0,
            "Resource": {"ResourceType": "AccessKey", "AccessKeyDetails": details}}


def _planned(raw: dict) -> list[tuple[str, str]]:
    return sorted((a.action_class.value, a.target) for a in plan_aws_actions(normalize_guardduty(raw)))


def test_a_long_term_user_key_is_disabled_and_the_user_denied() -> None:
    assert _planned(_key_finding("AKIAEXAMPLE1", "alice", "IAMUser")) == [
        ("attach_deny_all_to_principal", "alice"), ("disable_access_key", "AKIAEXAMPLE1")]


def test_a_users_session_token_denies_the_user_but_disables_nothing() -> None:
    """GetSessionToken credentials are temporary but belong to an IAM user."""
    assert _planned(_key_finding("ASIAEXAMPLE2", "alice", "IAMUser")) == [
        ("attach_deny_all_to_principal", "alice")]


def test_no_principal_action_when_the_principal_is_unknown() -> None:
    """Guessing would deny whatever IAM user happens to share the name."""
    assert _planned(_key_finding("ASIAEXAMPLE3", "data-sync", None)) == []
    assert _planned(_key_finding("ASIAEXAMPLE4", "web-federated", "FederatedUser")) == []
    assert _planned(_key_finding("AKIAEXAMPLE5", "root", "Root")) == []


def test_no_plan_ever_disables_a_temporary_key() -> None:
    for user_type in ("IAMUser", "AssumedRole", "FederatedUser", "Root", None):
        planned = _planned(_key_finding("ASIAEXAMPLE6", "x", user_type))
        assert not any(cls == "disable_access_key" for cls, _ in planned), user_type


def test_plan_aws_actions_instance_targets_the_real_instance(guardduty_findings) -> None:
    finding = normalize_guardduty(guardduty_findings[1])
    actions = plan_aws_actions(finding)
    classes = {a.action_class for a in actions}
    assert ActionClass.ISOLATE_INSTANCE_SG in classes
    assert ActionClass.TERMINATE_INSTANCE in classes
    for a in actions:
        if a.action_class in (ActionClass.ISOLATE_INSTANCE_SG, ActionClass.TERMINATE_INSTANCE):
            assert a.target == "i-0a1b2c3d4e5f60789"
            assert a.provider == "aws"


def test_plan_aws_actions_low_severity_recon_has_no_target_resource(guardduty_findings) -> None:
    # The recon finding still has an EC2 instance resource, so it still
    # produces candidate actions -- policy.min_severity is what blocks it, not
    # the planner. Confirm the planner itself is target-driven regardless.
    finding = normalize_guardduty(guardduty_findings[2])
    actions = plan_aws_actions(finding)
    assert all(a.target == "i-0999888777666555" for a in actions
               if a.action_class in (ActionClass.ISOLATE_INSTANCE_SG, ActionClass.TERMINATE_INSTANCE))


# --------------------------------------------------------------------------- #
# Kubernetes
# --------------------------------------------------------------------------- #

def test_normalize_k8s_privilege_escalation(k8s_audit_events) -> None:
    raw = k8s_audit_events[0]
    finding = normalize_k8s(raw)

    assert finding.provider == "kubernetes"
    assert finding.finding_id == "k8s-audit-privesc-0001"
    assert finding.severity == 8.5  # from the rule table
    assert finding.remote_ip == "10.0.9.14"
    kinds = {r.kind for r in finding.resources}
    assert kinds == {"k8s.pod", "k8s.node"}
    pod = next(r for r in finding.resources if r.kind == "k8s.pod")
    assert pod.id == "payments-api-7f9c8d"
    assert pod.attributes["namespace"] == "payments"
    node = next(r for r in finding.resources if r.kind == "k8s.node")
    assert node.id == "ip-10-0-3-51.ec2.internal"


def test_normalize_k8s_detector_severity_overrides_rule_table() -> None:
    payload = {
        "auditID": "custom-1", "objectRef": {"resource": "pods", "namespace": "ns", "name": "p"},
        "detected_rule": "privilege_escalation_exec", "detected_severity": 3.0,
    }
    finding = normalize_k8s(payload)
    assert finding.severity == 3.0  # explicit detector severity wins over the 8.5 default


def test_normalize_k8s_unknown_rule_defaults_reasonably() -> None:
    payload = {"auditID": "x", "objectRef": {}, "detected_rule": "some_new_rule_not_in_table"}
    finding = normalize_k8s(payload)
    assert finding.severity == 5.0
    assert finding.finding_type == "k8s:some_new_rule_not_in_table"


def test_plan_k8s_actions_pod_targets_the_real_pod(k8s_audit_events) -> None:
    finding = normalize_k8s(k8s_audit_events[0])
    actions = plan_k8s_actions(finding)

    pod_actions = {a.action_class: a for a in actions
                   if a.action_class in (ActionClass.ISOLATE_POD, ActionClass.DELETE_POD)}
    assert set(pod_actions) == {ActionClass.ISOLATE_POD, ActionClass.DELETE_POD}
    for a in pod_actions.values():
        assert a.target == "payments-api-7f9c8d"
        assert a.provider == "kubernetes"
        assert a.parameters["namespace"] == "payments"

    node_actions = [a for a in actions if a.action_class == ActionClass.CORDON_NODE]
    assert node_actions[0].target == "ip-10-0-3-51.ec2.internal"


def test_plan_k8s_actions_deployment_targets_the_real_deployment(k8s_audit_events) -> None:
    finding = normalize_k8s(k8s_audit_events[2])  # crypto_mining_pod on a deployment
    actions = plan_k8s_actions(finding)
    scale_actions = [a for a in actions if a.action_class == ActionClass.SCALE_DEPLOYMENT_ZERO]
    assert len(scale_actions) == 1
    assert scale_actions[0].target == "nginx-update-svc"
    assert scale_actions[0].parameters["namespace"] == "default"


def test_plan_k8s_actions_secret_enumeration_has_no_planner_for_secrets(k8s_audit_events) -> None:
    """secrets isn't a resource kind the planner recognizes -- no crash, just
    no candidate actions (matches the live-run behavior seen in production
    testing: 'no containment action available for this resource type')."""
    finding = normalize_k8s(k8s_audit_events[1])
    assert finding.resources == []
    actions = plan_k8s_actions(finding)
    assert actions == []


# --------------------------------------------------------------------------- #
# Registry dispatch
# --------------------------------------------------------------------------- #

_ALL_PROVIDERS = {"aws", "azure", "cloudflare", "gcp", "kubernetes", "onprem"}


def test_registry_has_all_providers() -> None:
    assert set(NORMALIZERS) == _ALL_PROVIDERS
    assert set(PLANNERS) == _ALL_PROVIDERS


def test_plan_actions_dispatches_by_finding_provider(guardduty_findings, k8s_audit_events) -> None:
    aws_finding = normalize_guardduty(guardduty_findings[0])
    k8s_finding = normalize_k8s(k8s_audit_events[0])

    aws_actions = plan_actions(aws_finding)
    k8s_actions = plan_actions(k8s_finding)

    assert all(a.provider == "aws" for a in aws_actions)
    assert all(a.provider == "kubernetes" for a in k8s_actions)
    assert aws_actions  # both non-empty for these fixtures
    assert k8s_actions


def test_plan_actions_unknown_provider_returns_empty_not_crash() -> None:
    from kronagent.model import Finding
    finding = Finding(provider="azure", finding_id="x", finding_type="t", severity=9.0)
    assert plan_actions(finding) == []


def test_build_containment_adapters_registers_all_providers() -> None:
    from kronagent.providers.gcp import GcpContainmentAdapter
    settings = Settings()
    adapters = build_containment_adapters(settings)
    assert set(adapters) == _ALL_PROVIDERS
    assert isinstance(adapters["aws"], AwsContainmentAdapter)
    assert isinstance(adapters["gcp"], GcpContainmentAdapter)
    assert isinstance(adapters["kubernetes"], K8sContainmentAdapter)


# --------------------------------------------------------------------------- #
# "Dry-run needs no credentials" -- a design claim from the module docstrings,
# proven here rather than trusted: adapter.plan() must never touch a lazy
# cloud/cluster client.
# --------------------------------------------------------------------------- #

def test_aws_adapter_plan_never_builds_a_boto3_client() -> None:
    adapter = AwsContainmentAdapter(region="us-east-1", quarantine_security_group_id="sg-fake")
    adapter._ec2_client = lambda: pytest.fail("plan() must not construct an EC2 client")
    adapter._iam_client = lambda: pytest.fail("plan() must not construct an IAM client")

    from .conftest import make_action
    for ac in [ActionClass.DISABLE_ACCESS_KEY, ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
               ActionClass.ISOLATE_INSTANCE_SG, ActionClass.BLOCK_IP,
               ActionClass.REVOKE_ROLE_SESSIONS, ActionClass.TERMINATE_INSTANCE]:
        calls, rollback, detail = adapter.plan(make_action(provider="aws", action_class=ac))
        assert calls and rollback and detail


def test_k8s_adapter_plan_never_builds_a_k8s_client() -> None:
    adapter = K8sContainmentAdapter()
    adapter._apis = lambda: pytest.fail("plan() must not construct a kubernetes API client")

    from .conftest import make_action
    for ac in [ActionClass.ISOLATE_POD, ActionClass.CORDON_NODE,
               ActionClass.DELETE_POD, ActionClass.SCALE_DEPLOYMENT_ZERO]:
        calls, rollback, detail = adapter.plan(make_action(provider="kubernetes", action_class=ac))
        assert calls and rollback and detail
