"""
What the in-account stack promises a customer, checked against the rendered
template rather than read off the source.
"""

from __future__ import annotations

import json
from pathlib import Path

from kronagent.aws_stack import render_stack
from kronagent.connect import _cfn_parameterize, _contain_policy, _observe_policy

STACK = render_stack()
RES = STACK["Resources"]
PARAMS = set(STACK["Parameters"])


def _env(name: str):
    container = RES["TaskDefinition"]["Properties"]["ContainerDefinitions"][0]
    return next(e["Value"] for e in container["Environment"] if e["Name"] == name)


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def test_the_committed_template_is_the_rendered_one() -> None:
    committed = json.loads(Path("deploy/cloudformation/kronagent-in-account.json").read_text())
    assert committed == STACK


def test_nothing_can_reach_the_task() -> None:
    task_sg = RES["TaskSecurityGroup"]["Properties"]
    assert "SecurityGroupIngress" not in task_sg
    ingress_rules = [r for r in RES.values() if r["Type"] == "AWS::EC2::SecurityGroupIngress"]
    assert ingress_rules == []
    # The only inbound rule in the stack: NFS to the state volume, from the task.
    state_in = RES["StateSecurityGroup"]["Properties"]["SecurityGroupIngress"]
    assert state_in == [{"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049,
                         "SourceSecurityGroupId": {"Ref": "TaskSecurityGroup"},
                         "Description": "NFS from the Kronagent task"}]
    assert not any(r["Type"].startswith("AWS::ElasticLoadBalancing") for r in RES.values())
    assert "PortMappings" not in RES["TaskDefinition"]["Properties"]["ContainerDefinitions"][0]


def test_the_task_role_observes_exactly_like_the_observe_role() -> None:
    policies = {p["PolicyName"]: p["PolicyDocument"]
                for p in RES["TaskRole"]["Properties"]["Policies"]}
    assert policies["KronagentObservePolicy"] == _cfn_parameterize(_observe_policy(), PARAMS)
    assert "KronagentContainPolicy" not in policies


def test_write_access_exists_only_when_containment_is_enabled() -> None:
    contain = RES["ContainPolicy"]
    assert contain["Condition"] == "ContainmentEnabled"
    assert STACK["Conditions"]["ContainmentEnabled"] == {"Fn::Equals": [{"Ref": "EnableContainment"}, "true"]}
    assert STACK["Parameters"]["EnableContainment"]["Default"] == "false"
    expected = _contain_policy("${AWS::AccountId}", "${AWS::Region}", "${QuarantineNaclId}",
                               "${QuarantineSecurityGroupId}", partition="${AWS::Partition}")
    assert contain["Properties"]["PolicyDocument"] == _cfn_parameterize(expected, PARAMS)


def test_dry_run_is_off_only_when_write_access_is_granted() -> None:
    assert _env("KRONAGENT_DRY_RUN") == {"Fn::If": ["ContainmentEnabled", "false", "true"]}


def test_no_irreversible_action_is_granted() -> None:
    assert not [s for s in _strings(STACK) if "TerminateInstances" in s]


def test_containment_cannot_be_enabled_without_its_quarantine_resources() -> None:
    rule = STACK["Rules"]["ContainmentNeedsQuarantineResources"]
    asserted = json.dumps(rule["Assertions"])
    assert "QuarantineSecurityGroupId" in asserted and "QuarantineNaclId" in asserted


def test_one_task_at_a_time() -> None:
    svc = RES["Service"]["Properties"]
    assert svc["DesiredCount"] == 1
    assert svc["DeploymentConfiguration"]["MaximumPercent"] == 100


def test_state_lives_on_the_retained_encrypted_volume() -> None:
    fs = RES["StateFileSystem"]
    assert fs["DeletionPolicy"] == "Retain" and fs["Properties"]["Encrypted"] is True
    mount = RES["TaskDefinition"]["Properties"]["ContainerDefinitions"][0]["MountPoints"][0]
    assert mount["ContainerPath"] == "/var/lib/kronagent"
    assert _env("KRONAGENT_STATE_DIR") == "/var/lib/kronagent"
    assert _env("KRONAGENT_DB_PATH").startswith("/var/lib/kronagent/")
    assert _env("KRONAGENT_OPERATOR_REGISTRY").startswith("/var/lib/kronagent/")
    volume = RES["TaskDefinition"]["Properties"]["Volumes"][0]["EFSVolumeConfiguration"]
    assert volume["TransitEncryption"] == "ENABLED"


def test_slack_tokens_are_secrets_not_environment() -> None:
    for name in ("SlackAppToken", "SlackBotToken"):
        assert STACK["Parameters"][name]["NoEcho"] is True
    container = RES["TaskDefinition"]["Properties"]["ContainerDefinitions"][0]
    env_names = {e["Name"] for e in container["Environment"]}
    assert not env_names & {"KRONAGENT_SLACK_APP_TOKEN", "KRONAGENT_SLACK_BOT_TOKEN"}
    secrets = container["Secrets"]["Fn::If"][1]
    assert {s["Name"] for s in secrets} == {"KRONAGENT_SLACK_APP_TOKEN", "KRONAGENT_SLACK_BOT_TOKEN"}


def test_only_the_guardduty_rule_may_feed_the_queue() -> None:
    stmt = RES["FindingsQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"]
    assert len(stmt) == 1
    assert stmt[0]["Principal"] == {"Service": "events.amazonaws.com"}
    assert stmt[0]["Condition"] == {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["FindingsRule", "Arn"]}}}
    assert RES["FindingsRule"]["Properties"]["EventPattern"]["source"] == ["aws.guardduty"]


def test_triage_runs_on_bedrock_in_this_account() -> None:
    assert _env("KRONAGENT_LLM") == "bedrock"
    assert _env("KRONAGENT_BEDROCK_MODEL") == {"Ref": "BedrockModel"}
    assert "GEMINI_API_KEY" not in json.dumps(STACK)


def test_the_image_is_pinned() -> None:
    image = STACK["Parameters"]["ImageUri"]["Default"]
    assert ":" in image.rsplit("/", 1)[-1] and not image.endswith(":latest")


def test_task_roles_trust_only_this_accounts_tasks() -> None:
    for role in ("TaskRole", "ExecutionRole"):
        stmt = RES[role]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
        assert stmt["Principal"] == {"Service": "ecs-tasks.amazonaws.com"}
        assert stmt["Condition"]["StringEquals"]["aws:SourceAccount"] == {"Fn::Sub": "${AWS::AccountId}"}
