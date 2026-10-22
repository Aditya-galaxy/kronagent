"""
The committed IAM artifacts are generated, and stay that way.

`deploy/cloudformation/*.json` and `deploy/kronagent-iam-policy.json` described
the same grant three times over, by hand. They had drifted four separate ways:
an inline policy name the adapter never writes, an action nothing calls, a NACL
grant covering every ACL in the account while `deploy/README.md` promised it
covered exactly one, and two missing read permissions without which containment
could not run at all. A fifth was asymmetric hardening — a region condition
present in one copy and absent from the other two.

None of that was carelessness. It is what maintaining one thing in three places
does, reliably, given time.

They render from `kronagent/connect.py` now. These tests are what stops that
regressing, and the load-bearing one is
`test_parameterized_and_baked_templates_grant_identical_policies`: it makes it
structurally impossible for the template a customer *downloads* and the template
a customer might one day *launch from a console link* to grant different things.
Generating both from one function is not sufficient on its own — the two forms
take different code paths through it, and only an assertion covers the gap.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.connect import (
    AwsConnection,
    Grant,
    new_external_id,
    render_template,
)

REPO = Path(__file__).resolve().parent.parent
KRONAGENT_ACCOUNT = "999988887777"
CUSTOMER_ACCOUNT = "123456789012"


def _conn() -> AwsConnection:
    return AwsConnection(
        tenant_id="acme",
        account_id=CUSTOMER_ACCOUNT,
        region="eu-west-2",
        external_id=new_external_id(),
        observe_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentObserveRole",
        contain_role_arn=f"arn:aws:iam::{CUSTOMER_ACCOUNT}:role/KronagentContainRole",
    )


def _policy_of(template: dict) -> dict:
    roles = [r for r in template["Resources"].values()
             if r["Type"] == "AWS::IAM::Role"]
    assert len(roles) == 1
    return roles[0]["Properties"]["Policies"][0]["PolicyDocument"]


def _shape(policy: dict) -> list[tuple]:
    """A policy reduced to what it permits, with the concrete ids abstracted.

    The two forms cannot be compared literally — one carries
    `arn:aws:ec2:eu-west-2:123456789012:...` and the other
    `{"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:..."}`. What must
    match is the Sid, the actions, the *number* of resources, and whether a
    condition is present. Anything beyond that is the substitution pass doing
    its job.
    """
    out = []
    for stmt in policy["Statement"]:
        actions = stmt["Action"]
        resource = stmt.get("Resource")
        out.append((
            stmt["Sid"],
            stmt["Effect"],
            tuple(sorted([actions] if isinstance(actions, str) else actions)),
            1 if not isinstance(resource, list) else len(resource),
            tuple(sorted(stmt.get("Condition", {}))),
        ))
    return sorted(out)


# --- The property that makes one source actually one source ------------------

@pytest.mark.parametrize("grant", list(Grant))
def test_parameterized_and_baked_templates_grant_identical_policies(grant):
    """The hosted grant and the downloaded grant must mean the same thing.

    They were separate files and drifted four ways. They share a function now,
    but the two forms still take different paths through it — so this asserts
    the outcome rather than trusting the structure.
    """
    conn = _conn()
    baked = render_template(conn, grant, kronagent_account_id=KRONAGENT_ACCOUNT,
                            quarantine_nacl_id="acl-1", quarantine_sg_id="sg-1")
    parameterized = render_template(conn, grant,
                                    kronagent_account_id=KRONAGENT_ACCOUNT,
                                    parameterized=True)

    assert _shape(_policy_of(baked)) == _shape(_policy_of(parameterized))


@pytest.mark.parametrize("grant", list(Grant))
def test_only_the_baked_form_carries_the_external_id(grant):
    """The External ID is a secret, and the baked form is the safer one.

    Baked, it cannot be omitted or mistyped. Parameterized, the customer supplies
    it — and a fat-fingered `KronagentAccountId` there creates a role trusting a
    stranger's AWS account, a silent and complete confused-deputy compromise.
    That asymmetry is the whole reason the download path stays primary, so it is
    asserted rather than assumed.
    """
    conn = _conn()
    baked = json.dumps(render_template(conn, grant,
                                       kronagent_account_id=KRONAGENT_ACCOUNT))
    parameterized = json.dumps(render_template(
        conn, grant, kronagent_account_id=KRONAGENT_ACCOUNT, parameterized=True))

    assert conn.external_id in baked
    assert KRONAGENT_ACCOUNT in baked
    assert conn.external_id not in parameterized, (
        "a per-tenant secret reached a template meant to be published once and "
        "installed by many")
    assert KRONAGENT_ACCOUNT not in parameterized


def test_the_baked_form_declares_no_parameters():
    """Nothing to fill in is the point. A parameter here is a blank a customer
    could leave blank."""
    for grant in Grant:
        tpl = render_template(_conn(), grant, kronagent_account_id=KRONAGENT_ACCOUNT)
        assert "Parameters" not in tpl


# --- The committed files are build output ------------------------------------

def test_committed_artifacts_match_the_renderer():
    """`publish_templates.py --check`, as a test.

    A hand edit to these files is exactly how the contain role came to pin an
    inline policy name the adapter never writes — granted, and denied, and
    invisible to every check that looked at action names.
    """
    res = subprocess.run(
        [sys.executable, "deploy/publish_templates.py", "--check"],
        cwd=REPO, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_every_declared_parameter_is_referenced():
    """A parameter the template never uses asks for a value that changes
    nothing — and reads, to a reviewer, as a scope being applied when it is
    not. `QuarantineSecurityGroupId` and `QuarantineNaclId` were both declared
    and both ignored, while the README described the scoping they implied."""
    for path in sorted((REPO / "deploy" / "cloudformation").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        body = json.dumps(doc["Resources"])
        unused = {p for p in doc.get("Parameters", {}) if p not in body}
        assert not unused, f"{path.name}: declared but never referenced: {sorted(unused)}"


def test_committed_templates_are_valid_json_with_one_role_each():
    # The cross-account role templates only. The in-account stack runs
    # Kronagent itself and has two roles by design; tests/test_aws_stack.py
    # holds its own guarantees.
    for path in sorted((REPO / "deploy" / "cloudformation").glob("kronagent-*-role.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["AWSTemplateFormatVersion"] == "2010-09-09"
        roles = [r for r in doc["Resources"].values()
                 if r["Type"] == "AWS::IAM::Role"]
        assert len(roles) == 1, f"{path.name} declares {len(roles)} roles"
        assert "RoleArn" in doc["Outputs"], (
            f"{path.name}: the customer has to paste this back into Kronagent")


def test_the_external_id_parameter_is_noecho():
    """CloudFormation echoes parameter values in the console, in stack events
    and in `describe-stacks` output. NoEcho keeps a per-tenant secret out of
    all three."""
    path = REPO / "deploy" / "cloudformation" / "kronagent-observe-role.json"
    params = json.loads(path.read_text(encoding="utf-8"))["Parameters"]
    assert params["ExternalId"].get("NoEcho") is True


def test_publish_script_reports_drift_rather_than_silently_passing(tmp_path):
    """`--check` is a CI gate. A gate that cannot fail is decoration."""
    target = REPO / "deploy" / "kronagent-iam-policy.json"
    original = target.read_text(encoding="utf-8")
    try:
        doc = json.loads(original)
        doc["Statement"][0]["Action"] = "iam:*"
        target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

        res = subprocess.run(
            [sys.executable, "deploy/publish_templates.py", "--check"],
            cwd=REPO, capture_output=True, text=True)
        assert res.returncode == 1
        assert "DRIFTED" in res.stdout
    finally:
        target.write_text(original, encoding="utf-8")


# --- Partitions --------------------------------------------------------------

@pytest.mark.parametrize("region,partition", [
    ("us-east-1", "aws"),
    ("eu-west-2", "aws"),
    ("us-gov-west-1", "aws-us-gov"),
    ("cn-north-1", "aws-cn"),
])
def test_baked_arns_use_the_partition_the_region_belongs_to(region, partition):
    """`_REGION_RE` accepts GovCloud regions, so the code already claims to
    support them — and every ARN hardcoded `arn:aws:`, the commercial partition.
    A GovCloud customer's stack would have created a role referencing resources
    that cannot exist in their partition. cfn-lint flags exactly this (I3042);
    it was flagging it on both templates before this change.
    """
    conn = AwsConnection(
        tenant_id="acme", account_id=CUSTOMER_ACCOUNT, region=region,
        external_id=new_external_id(),
        observe_role_arn=f"arn:{partition}:iam::{CUSTOMER_ACCOUNT}:role/R",
        contain_role_arn=f"arn:{partition}:iam::{CUSTOMER_ACCOUNT}:role/C",
    )
    body = json.dumps(render_template(conn, Grant.CONTAIN,
                                      kronagent_account_id=KRONAGENT_ACCOUNT,
                                      quarantine_nacl_id="acl-1",
                                      quarantine_sg_id="sg-1"))
    assert f"arn:{partition}:" in body
    if partition != "aws":
        assert "arn:aws:iam" not in body and "arn:aws:ec2" not in body, (
            f"a {region} role still references the commercial partition")


def test_parameterized_arns_defer_the_partition_to_cloudformation():
    """One hosted template has to work in every partition it is installed in,
    which only `${AWS::Partition}` can do."""
    body = json.dumps(render_template(_conn(), Grant.CONTAIN,
                                      kronagent_account_id=KRONAGENT_ACCOUNT,
                                      parameterized=True))
    assert "${AWS::Partition}" in body
    assert "arn:aws:ec2" not in body
