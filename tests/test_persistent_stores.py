"""
Unit tests for persistent SQLite stores for Campaign Memory and the Approval Store.
"""

from __future__ import annotations

import pytest
from kronagent.correlation import CorrelationMemory
from kronagent.approvals import ApprovalStore, ApprovalRequest
from kronagent.model import Finding, ResourceRef
from kronagent.schemas import ActionClass


def test_correlation_memory_sqlite(tmp_path) -> None:
    db_path = str(tmp_path / "campaign_memory.db")
    
    # 1. Initialize and verify table creation
    mem = CorrelationMemory(db_path=db_path, maxlen=3, capacity=3)
    assert len(mem) == 0

    # 2. Add findings and verify counts
    f1 = Finding(finding_id="f1", provider="aws", finding_type="exfil", severity=5.0, title="Exfil", resources=[ResourceRef(id="res1", kind="s3")])
    f2 = Finding(finding_id="f2", provider="aws", finding_type="mining", severity=6.0, title="Mining", resources=[ResourceRef(id="res2", kind="ec2")])
    f3 = Finding(finding_id="f3", provider="aws", finding_type="scan", severity=2.0, title="Scan", resources=[])
    
    mem.add(f1)
    mem.add(f2)
    mem.add(f3)
    assert len(mem) == 3

    # 3. Verify prior_to logic
    prior = mem.prior_to("f3")
    assert len(prior) == 2
    assert prior[0].finding_id == "f1"
    assert prior[1].finding_id == "f2"

    # 4. Verify the store's own bound (capacity=3)
    f4 = Finding(finding_id="f4", provider="aws", finding_type="rce", severity=9.0, title="RCE", resources=[])
    mem.add(f4)
    assert len(mem) == 3 # stayed at capacity

    # Verify f1 was deleted (oldest)
    prior_f4 = mem.prior_to("f4")
    assert len(prior_f4) == 2
    assert [p.finding_id for p in prior_f4] == ["f2", "f3"]


def test_correlation_memory_in_memory_fallback() -> None:
    # Verify fallback to standard deque when no db_path is specified
    mem = CorrelationMemory(db_path="", maxlen=2, capacity=2)
    assert len(mem) == 0

    f1 = Finding(finding_id="f1", provider="aws", finding_type="exfil", severity=5.0, title="Exfil", resources=[])
    f2 = Finding(finding_id="f2", provider="aws", finding_type="mining", severity=6.0, title="Mining", resources=[])
    f3 = Finding(finding_id="f3", provider="aws", finding_type="scan", severity=2.0, title="Scan", resources=[])

    mem.add(f1)
    mem.add(f2)
    mem.add(f3)
    assert len(mem) == 2 # rolled over in-memory

    prior = mem.prior_to("f3")
    assert len(prior) == 1
    assert prior[0].finding_id == "f2"


def test_approval_store_sqlite(tmp_path) -> None:
    db_path = str(tmp_path / "approvals.db")
    store = ApprovalStore(db_path)

    # 1. Add request
    req1 = ApprovalRequest(
        finding_id="f1",
        finding_type="exfil",
        severity=7.5,
        provider="aws",
        action_class=ActionClass.BLOCK_IP,
        target="1.1.1.1",
        rationale="Block attacker IP",
        policy_reason="blast radius limit",
        reversible=True,
        blast_radius="medium",
        mitre_techniques=["T1020"],
        threat_intel_summary="IP matches Tor exit node",
        related_finding_ids=["prev-f0"],
        correlation_summary="Part of campaign-12",
        incident_priority="high",
        escalated=True,
        incident_narrative="compromised host scanning",
        evidence_collected=["network flows"],
    )
    store.add(req1)

    # 2. Get and verify fields
    retrieved = store.get(req1.request_id)
    assert retrieved is not None
    assert retrieved.finding_id == "f1"
    assert retrieved.severity == 7.5
    assert retrieved.action_class == ActionClass.BLOCK_IP
    assert retrieved.target == "1.1.1.1"
    assert retrieved.mitre_techniques == ["T1020"]
    assert retrieved.related_finding_ids == ["prev-f0"]
    assert retrieved.escalated is True
    assert retrieved.evidence_collected == ["network flows"]
    assert retrieved.status == "pending"

    # 3. List requests
    all_requests = store.list()
    assert len(all_requests) == 1
    assert all_requests[0].request_id == req1.request_id

    # List by status
    pending_only = store.list(status="pending")
    assert len(pending_only) == 1
    approved_only = store.list(status="approved")
    assert len(approved_only) == 0

    # 4. Update request
    retrieved.status = "approved"
    retrieved.decided_by = "secops-operator"
    retrieved.decided_at = "2026-07-22T12:00:00Z"
    retrieved.decision_reason = "Approved containment"
    store.update(retrieved)

    updated = store.get(req1.request_id)
    assert updated.status == "approved"
    assert updated.decided_by == "secops-operator"
    assert updated.decision_reason == "Approved containment"

    # Check list by status again
    assert len(store.list(status="pending")) == 0
    assert len(store.list(status="approved")) == 1

    # 5. Error case
    fake_req = ApprovalRequest(
        request_id="apr-fake",
        finding_id="f2",
        finding_type="mining",
        severity=1.0,
        action_class=ActionClass.BLOCK_IP,
        target="2.2.2.2",
        rationale="reason",
        policy_reason="policy",
        reversible=False,
        blast_radius="low",
    )
    with pytest.raises(KeyError):
        store.update(fake_req)
