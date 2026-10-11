"""
Integration/high-fidelity testing of AWS containment actions using Moto.
"""

from __future__ import annotations

import json

import pytest

# These exercise the real AWS containment path against moto, so they need the
# AWS SDK. The core install deliberately ships without it — skip rather than
# fail collection, so `pip install kronagent && pytest` stays green for someone
# who never intends to touch AWS. CI runs a separate job with [all,dev] where
# these do execute.
boto3 = pytest.importorskip("boto3")
mock_aws = pytest.importorskip("moto").mock_aws

from kronagent.providers.aws import AwsContainmentAdapter
from kronagent.schemas import ActionClass, ProposedAction


@mock_aws
def test_moto_block_ip_success() -> None:
    # 1. Setup mock AWS environment (VPC and NACL)
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    nacl = ec2_client.create_network_acl(VpcId=vpc_id)
    nacl_id = nacl["NetworkAcl"]["NetworkAclId"]

    # 2. Initialize our containment adapter targeting the mock NACL
    adapter = AwsContainmentAdapter(region="us-east-1", quarantine_nacl_id=nacl_id)

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.BLOCK_IP,
        target="198.51.100.42",
        rationale="Block command-and-control IP",
    )

    # 3. Perform the containment action
    detail, rollback = adapter._perform_sync(action)

    assert "blocked at quarantine NACL" in detail
    assert nacl_id in detail

    # 4. Query the mock NACL state to verify the entries are actually created in Moto!
    acls = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = acls["NetworkAcls"][0]["Entries"]

    # Check for ingress block rule
    ingress_entries = [e for e in entries if not e["Egress"] and e["CidrBlock"] == "198.51.100.42/32"]
    assert len(ingress_entries) == 1
    assert ingress_entries[0]["RuleAction"] == "deny"

    # Check for egress block rule
    egress_entries = [e for e in entries if e["Egress"] and e["CidrBlock"] == "198.51.100.42/32"]
    assert len(egress_entries) == 1
    assert egress_entries[0]["RuleAction"] == "deny"


@mock_aws
def test_moto_revoke_role_sessions_success() -> None:
    # 1. Setup mock AWS environment (IAM Role)
    iam_client = boto3.client("iam", region_name="us-east-1")
    role_name = "test-compromised-role"

    # Assume role policy document
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
    )

    # 2. Initialize our containment adapter
    adapter = AwsContainmentAdapter(region="us-east-1")

    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.REVOKE_ROLE_SESSIONS,
        target=role_name,
        rationale="Revoke sessions for compromised role",
    )

    # 3. Perform the containment action
    detail, rollback = adapter._perform_sync(action)

    assert "active sessions revoked for role" in detail
    assert role_name in detail

    # 4. Verify that the inline revocation policy was actually attached to the IAM role in Moto!
    policies = iam_client.list_role_policies(RoleName=role_name)
    assert "kronagent-revoke-sessions" in policies["PolicyNames"]

    policy_detail = iam_client.get_role_policy(
        RoleName=role_name, PolicyName="kronagent-revoke-sessions"
    )
    policy_doc = policy_detail["PolicyDocument"]
    if isinstance(policy_doc, str):
        import urllib.parse
        doc = json.loads(urllib.parse.unquote(policy_doc))
    else:
        doc = policy_doc

    # Assert policy denies everything
    assert doc["Statement"][0]["Effect"] == "Deny"
    assert doc["Statement"][0]["Action"] == "*"
    assert doc["Statement"][0]["Resource"] == "*"
    assert "DateLessThan" in doc["Statement"][0]["Condition"]


# --- release: contain, then undo, against emulated AWS ------------------------

@mock_aws
def test_moto_access_key_is_disabled_then_released_to_active() -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="svc-backup")
    key_id = iam.create_access_key(UserName="svc-backup")["AccessKey"]["AccessKeyId"]
    adapter = AwsContainmentAdapter(region="us-east-1")
    action = ProposedAction(provider="aws", action_class=ActionClass.DISABLE_ACCESS_KEY, target=key_id,
                            rationale="exfiltration", parameters={"user_name": "svc-backup"})

    def status() -> str:
        return iam.list_access_keys(UserName="svc-backup")["AccessKeyMetadata"][0]["Status"]

    adapter._perform_sync(action)
    assert status() == "Inactive"
    assert adapter.plan_release(action)[0] == [
        f"iam.update_access_key(UserName='svc-backup', AccessKeyId='{key_id}', Status='Active')"]
    assert adapter._release_sync(action) == f"access key {key_id} set Active"
    assert status() == "Active"
    adapter._release_sync(action)                      # a second release changes nothing
    assert status() == "Active"


@mock_aws
def test_moto_ip_block_is_released_and_nothing_else_in_the_nacl_is_touched() -> None:
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    nacl_id = ec2.create_network_acl(VpcId=vpc_id)["NetworkAcl"]["NetworkAclId"]
    # Rules that are not ours: another blocked address, and an allow rule for the same one.
    ec2.create_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=100, Protocol="-1", RuleAction="deny",
                                 Egress=False, CidrBlock="203.0.113.9/32")
    ec2.create_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=50, Protocol="6", RuleAction="allow",
                                 Egress=False, CidrBlock="198.51.100.42/32", PortRange={"From": 443, "To": 443})
    adapter = AwsContainmentAdapter(region="us-east-1", quarantine_nacl_id=nacl_id)
    action = ProposedAction(provider="aws", action_class=ActionClass.BLOCK_IP, target="198.51.100.42",
                            rationale="c2")

    def rules() -> set[tuple]:
        entries = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]["Entries"]
        return {(e["RuleNumber"], e["Egress"], e["RuleAction"], e.get("CidrBlock")) for e in entries}

    before = rules()
    adapter._perform_sync(action)
    assert len(rules() - before) == 2                   # one deny each way for this address
    assert "removed 2 deny rule(s) for 198.51.100.42" in adapter._release_sync(action)
    assert rules() == before                            # the other block and the allow rule are still there
    assert "nothing to remove" in adapter._release_sync(action)
    assert rules() == before
