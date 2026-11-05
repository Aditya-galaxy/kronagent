"""
Forensics Agent — evidence planning and chain of custody.

Two properties matter most here:
  1. Evidence targets come from the finding's normalized resources, never from
     a model (same anti-injection discipline as containment).
  2. The custody record is tamper-evident, because it lands in the hash-chained
     audit log — editing a custody record after the fact must break chain
     verification. That's the whole basis for the evidence being defensible, so
     it's proven, not asserted.
"""

from __future__ import annotations

import json

import pytest

from kronagent.audit import AuditLog
from kronagent.forensics import COLLECTOR, EvidenceItem, ForensicsAgent
from kronagent.model import Finding, ResourceRef


def _aws_instance_finding() -> Finding:
    return Finding(
        provider="aws", finding_id="f-aws-1", finding_type="CryptoCurrency:EC2/BitcoinTool",
        severity=7.5,
        resources=[ResourceRef(kind="aws.ec2.instance", id="i-0abc123")],
    )


def _aws_key_finding() -> Finding:
    return Finding(
        provider="aws", finding_id="f-aws-2", finding_type="UnauthorizedAccess:IAMUser",
        severity=8.0,
        resources=[
            ResourceRef(kind="aws.iam.access_key", id="AKIA1", attributes={"user_name": "svc-backup"}),
            ResourceRef(kind="aws.iam.user", id="svc-backup"),
        ],
    )


def _k8s_pod_finding() -> Finding:
    return Finding(
        provider="kubernetes", finding_id="f-k8s-1", finding_type="k8s:privilege_escalation_exec",
        severity=8.5,
        resources=[
            ResourceRef(kind="k8s.pod", id="payments-api-7f9c8d", attributes={"namespace": "payments"}),
            ResourceRef(kind="k8s.node", id="ip-10-0-3-51"),
        ],
    )


@pytest.fixture
def agent(settings) -> ForensicsAgent:
    return ForensicsAgent(settings)


# --------------------------------------------------------------------------- #
# Evidence planning — deterministic, target-driven
# --------------------------------------------------------------------------- #

async def test_ec2_instance_evidence_targets_the_real_instance(agent, audit_log) -> None:
    result = await agent.collect(_aws_instance_finding(), audit_log)
    assert result.items
    assert all(i.target == "i-0abc123" for i in result.items)
    kinds = set(result.evidence_kinds())
    assert "aws.ebs.snapshot" in kinds
    assert "aws.ec2.metadata" in kinds


async def test_iam_finding_collects_cloudtrail_for_the_principal(agent, audit_log) -> None:
    result = await agent.collect(_aws_key_finding(), audit_log)
    trail = [i for i in result.items if i.kind == "aws.cloudtrail.history"]
    assert trail
    # Target must be the principal from the finding, not the raw key id.
    assert any(i.target == "svc-backup" for i in trail)


async def test_duplicate_evidence_is_collected_once_not_per_resource(agent, audit_log) -> None:
    """The access-key resource and the user resource both resolve to the same
    principal's CloudTrail history -- must produce exactly one custody record
    for it, not one per resource that happens to name it."""
    result = await agent.collect(_aws_key_finding(), audit_log)
    trail = [i for i in result.items if i.kind == "aws.cloudtrail.history" and i.target == "svc-backup"]
    assert len(trail) == 1


async def test_pod_evidence_covers_logs_and_manifest(agent, audit_log) -> None:
    result = await agent.collect(_k8s_pod_finding(), audit_log)
    kinds = set(result.evidence_kinds())
    assert "k8s.pod.logs" in kinds
    assert "k8s.pod.manifest" in kinds
    assert "k8s.node.describe" in kinds
    # Namespace from the finding must appear in the concrete collection command.
    logs = next(i for i in result.items if i.kind == "k8s.pod.logs")
    assert "-n payments" in logs.collection_calls[0]


async def test_unknown_provider_collects_nothing_without_crashing(agent, audit_log) -> None:
    finding = Finding(provider="azure", finding_id="f-x", finding_type="T", severity=9.0)
    result = await agent.collect(finding, audit_log)
    assert result.items == []


async def test_finding_with_no_resources_collects_nothing(agent, audit_log) -> None:
    finding = Finding(provider="aws", finding_id="f-y", finding_type="T", severity=9.0)
    result = await agent.collect(finding, audit_log)
    assert result.items == []


async def test_snapshot_is_flagged_as_mutating_while_reads_are_not(agent, audit_log) -> None:
    """Creating a snapshot mutates account state (a new resource, billable);
    reading metadata does not. The distinction has to be explicit so an operator
    can reason about what evidence collection actually does."""
    result = await agent.collect(_aws_instance_finding(), audit_log)
    snap = next(i for i in result.items if i.kind == "aws.ebs.snapshot")
    meta = next(i for i in result.items if i.kind == "aws.ec2.metadata")
    assert snap.read_only is False
    assert meta.read_only is True


# --------------------------------------------------------------------------- #
# Chain of custody
# --------------------------------------------------------------------------- #

async def test_every_evidence_item_gets_a_custody_hash(agent, audit_log) -> None:
    result = await agent.collect(_aws_instance_finding(), audit_log)
    for item in result.items:
        assert len(item.custody_sha256) == 64  # sha256 hex
        assert item.collector == COLLECTOR


def test_custody_hash_is_deterministic_over_the_manifest() -> None:
    item = EvidenceItem(
        evidence_id="evd-fixed", kind="aws.ebs.snapshot", target="i-1",
        description="d", collection_calls=["call()"], collected_at="2026-01-01T00:00:00+00:00",
    )
    a = item.with_custody_hash().custody_sha256
    b = item.with_custody_hash().custody_sha256
    assert a == b and len(a) == 64


def test_custody_hash_changes_if_the_evidence_identity_changes() -> None:
    base = EvidenceItem(
        evidence_id="evd-fixed", kind="aws.ebs.snapshot", target="i-1",
        description="d", collection_calls=["call()"], collected_at="2026-01-01T00:00:00+00:00",
    )
    tampered = base.model_copy(update={"target": "i-ATTACKER"})
    assert base.with_custody_hash().custody_sha256 != tampered.with_custody_hash().custody_sha256


async def test_custody_records_land_in_the_audit_log(agent, audit_log, settings) -> None:
    result = await agent.collect(_aws_instance_finding(), audit_log)
    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    forensic = [r for r in records if r["stage"] == "forensics"]

    assert len(forensic) == len(result.items)
    for r in forensic:
        p = r["payload"]
        assert p["custody_sha256"]
        assert p["collector"] == COLLECTOR
        assert p["target"] == "i-0abc123"
        assert "collection_calls" in p


async def test_tampering_with_a_custody_record_breaks_chain_verification(
    agent, audit_log, settings
) -> None:
    """The load-bearing claim of 'chain of custody': you cannot quietly rewrite
    what evidence was collected after the fact."""
    await agent.collect(_aws_instance_finding(), audit_log)
    assert AuditLog.verify(settings.audit_log_path)[0] is True

    with open(settings.audit_log_path) as fh:
        lines = fh.readlines()
    rec = json.loads(lines[0])
    rec["record"]["payload"]["target"] = "i-SOMETHING-ELSE"   # rewrite the evidence source
    lines[0] = json.dumps(rec) + "\n"
    with open(settings.audit_log_path, "w") as fh:
        fh.writelines(lines)

    ok, broken = AuditLog.verify(settings.audit_log_path)
    assert ok is False
    assert broken == 1


async def test_dry_run_records_custody_without_marking_evidence_collected(
    agent, audit_log, settings
) -> None:
    """In dry-run the plan and custody record are complete, but nothing claims
    to have actually been collected -- the record must not overstate."""
    assert settings.dry_run is True
    result = await agent.collect(_aws_instance_finding(), audit_log)
    assert result.items
    assert all(i.collected is False for i in result.items)

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    forensic = [r for r in records if r["stage"] == "forensics"]
    assert all(r["payload"]["dry_run"] is True for r in forensic)
    assert all(r["payload"]["collected"] is False for r in forensic)


async def test_live_mode_does_not_falsely_claim_collection(settings, audit_log) -> None:
    """Live execution isn't wired yet. The agent must be honest about that --
    recording the custody plan but never asserting evidence was captured."""
    import dataclasses
    live = dataclasses.replace(settings, dry_run=False)
    result = await ForensicsAgent(live).collect(_aws_instance_finding(), audit_log)
    assert all(i.collected is False for i in result.items)
    assert any("not yet wired" in i.description for i in result.items)


def test_evidence_item_custody_verification() -> None:
    item = EvidenceItem(
        kind="aws.ebs.snapshot",
        target="i-12345",
        description="EBS snapshot",
    ).with_custody_hash()

    assert item.verify_custody() is True

    # Mutate the manifest data post-hash computation
    item_tampered = item.model_copy(update={"target": "i-tampered"})
    assert item_tampered.verify_custody() is False



def test_stolen_session_evidence_traces_the_key_and_snapshots_the_role() -> None:
    """Temporary credentials are traced by key in CloudTrail, and the role's
    policies are captured before revoking its sessions changes them."""
    from kronagent.forensics import _plan_aws_evidence
    finding = Finding(
        provider="aws", finding_id="f-sess", finding_type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        severity=8.0,
        resources=[
            ResourceRef(kind="aws.sts.temporary_credentials", id="ASIA1", attributes={"user_name": "svc-backup"}),
            ResourceRef(kind="aws.iam.role", id="svc-backup"),
        ],
    )
    items = _plan_aws_evidence(finding)
    assert any("AccessKeyId='ASIA1'" in c for i in items for c in i.collection_calls)
    assert any(i.kind == "aws.iam.role.state" and i.target == "svc-backup" for i in items)
    assert all(i.read_only for i in items)
