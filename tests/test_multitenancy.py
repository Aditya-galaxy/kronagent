"""
Unit and integration tests for the Kronagent Multi-Tenancy and Business-Unit isolation.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from kronagent.model import Finding
from kronagent.orchestrator import Orchestrator, get_tenant_path
from kronagent.config import Settings
from kronagent.policy import PolicyEngine
from kronagent.containment import ContainmentExecutor
from kronagent.audit import AuditLog
from kronagent.approvals import ApprovalStore
from kronagent.allowlist import AllowlistStore
from kronagent.schemas import ActionClass, ProposedAction


@pytest.fixture
def temp_settings_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def test_get_tenant_path():
    base_audit = "/tmp/kronagent_audit.jsonl"
    assert get_tenant_path(base_audit, "default") == base_audit
    assert get_tenant_path(base_audit, "") == base_audit
    assert get_tenant_path(base_audit, "tenant-a") == "/tmp/kronagent_audit_tenant-a.jsonl"
    
    base_db = "/tmp/kronagent.db"
    assert get_tenant_path(base_db, "tenant-b") == "/tmp/kronagent_tenant-b.db"


@pytest.mark.asyncio
async def test_orchestrator_tenant_isolation(temp_settings_dir) -> None:
    # 1. Setup temp file paths in settings
    audit_path = os.path.join(temp_settings_dir, "audit.jsonl")
    approvals_path = os.path.join(temp_settings_dir, "approvals.json")
    allowlist_path = os.path.join(temp_settings_dir, "allowlist.json")
    db_path = os.path.join(temp_settings_dir, "kronagent.db")
    
    settings = Settings(
        audit_log_path=audit_path,
        approval_store_path=approvals_path,
        allowlist_store_path=allowlist_path,
        db_path=db_path,
        dry_run=True,
        kill_switch=False,
        min_severity_for_containment=5.0
    )
    
    # 2. Mock adapters/triager
    from unittest.mock import MagicMock, AsyncMock
    triage = MagicMock()
    # Mock assess to return an actionable threat with block_ip candidate
    from kronagent.triage import TriageVerdict
    from kronagent.schemas import ProposedAction, ActionClass
    verdict = TriageVerdict(
        finding_id="f-1",
        is_actionable_threat=True,
        threat_category="exfiltration",
        confidence=0.95,
        severity=8.0,
        justification="compromised host"
    )
    candidates = [
        ProposedAction(
            provider="aws",
            action_class=ActionClass.BLOCK_IP,
            target="1.2.3.4",
            rationale="exfiltration"
        )
    ]
    triage.assess = AsyncMock(return_value=(verdict, candidates))
    
    # Policy and containment
    from kronagent.providers import build_containment_adapters
    policy = PolicyEngine(settings, AllowlistStore(allowlist_path))
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))
    
    correlation = AsyncMock()
    from kronagent.correlation import CorrelationAssessment
    correlation.assess = AsyncMock(return_value=CorrelationAssessment(
        finding_id="f-1",
        available=True,
        part_of_campaign=False,
        related_finding_ids=[],
        correlation_summary="no correlation"
    ))

    # Build orchestrator
    orchestrator = Orchestrator(
        settings=settings,
        triage=triage,
        policy=policy,
        containment=containment,
        audit=AuditLog(audit_path),
        approvals=ApprovalStore(approvals_path),
        correlation=correlation
    )
    
    # 3. Handle tenant-a finding
    finding_a = Finding(
        provider="aws",
        finding_id="finding-a",
        finding_type="GuardDuty:Exfiltration",
        severity=8.0,
        tenant_id="tenant-a",
        title="Exfiltration detected"
    )
    await orchestrator._handle(finding_a)
    
    # Handle tenant-b finding
    finding_b = Finding(
        provider="aws",
        finding_id="finding-b",
        finding_type="GuardDuty:Exfiltration",
        severity=8.0,
        tenant_id="tenant-b",
        title="Exfiltration detected"
    )
    await orchestrator._handle(finding_b)
    
    # 4. Assert files are written separately
    audit_a_path = get_tenant_path(audit_path, "tenant-a")
    audit_b_path = get_tenant_path(audit_path, "tenant-b")
    
    assert os.path.exists(audit_a_path)
    assert os.path.exists(audit_b_path)
    assert not os.path.exists(audit_path)  # The default empty log should not have anything
    
    # Verify content isolation in audit logs
    with open(audit_a_path, "r") as f:
        content_a = f.read()
        assert "finding-a" in content_a
        assert "finding-b" not in content_a
        
    with open(audit_b_path, "r") as f:
        content_b = f.read()
        assert "finding-b" in content_b
        assert "finding-a" not in content_b

    # Verify separate approval queues
    appr_a_path = get_tenant_path(approvals_path, "tenant-a")
    appr_b_path = get_tenant_path(approvals_path, "tenant-b")
    
    assert os.path.exists(appr_a_path)
    assert os.path.exists(appr_b_path)
    
    store_a = ApprovalStore(appr_a_path)
    store_b = ApprovalStore(appr_b_path)
    
    list_a = store_a.list()
    list_b = store_b.list()
    
    assert len(list_a) == 1
    assert list_a[0].finding_id == "finding-a"
    
    assert len(list_b) == 1
    assert list_b[0].finding_id == "finding-b"


@pytest.mark.asyncio
async def test_policy_allowlist_tenant_isolation(temp_settings_dir) -> None:
    # 1. Setup paths
    allowlist_path = os.path.join(temp_settings_dir, "allowlist.json")
    settings = Settings(
        allowlist_store_path=allowlist_path,
        min_severity_for_containment=5.0
    )
    
    # 2. Instantiate PolicyEngine
    policy = PolicyEngine(settings, AllowlistStore(allowlist_path))
    
    # 3. Promote BLOCK_IP for tenant-a
    allowlist_a = AllowlistStore(get_tenant_path(allowlist_path, "tenant-a"))
    from kronagent.audit import AuditLog
    audit_a = AuditLog(os.path.join(temp_settings_dir, "audit_a.jsonl"))
    await allowlist_a.add(ActionClass.BLOCK_IP, providers=["aws"], by="admin", reason="approved", audit=audit_a)
    
    # 4. Check policy decision for tenant-a (should be auto_execute)
    action = ProposedAction(
        provider="aws",
        action_class=ActionClass.BLOCK_IP,
        target="1.2.3.4",
        rationale="compromised host"
    )
    dec_a = policy.decide(action, severity=7.0, allowlist=allowlist_a)
    assert dec_a.disposition == "auto_execute"
    
    # Check policy decision for tenant-b (should be requires_approval)
    allowlist_b = AllowlistStore(get_tenant_path(allowlist_path, "tenant-b"))
    dec_b = policy.decide(action, severity=7.0, allowlist=allowlist_b)
    assert dec_b.disposition == "requires_approval"
