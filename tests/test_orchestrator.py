"""
Orchestrator — sequencing, audit completeness, approval creation, and the
at-least-once ack contract. Uses fakes for triage/policy so each test controls
exactly one variable (the triage verdict, or the policy disposition) without
depending on LLM calls or severity-threshold arithmetic.
"""

from __future__ import annotations

import asyncio
import json
from typing import Callable


from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.containment import ContainmentExecutor
from kronagent.ingestion import QueuedFinding
from kronagent.model import Finding
from kronagent.orchestrator import Orchestrator
from kronagent.schemas import ActionClass, PolicyDecision, ProposedAction, TriageVerdict

from .conftest import FakeContainmentAdapter, make_decision


class FakeTriageEngine:
    """Returns a pre-scripted (verdict, candidates) pair -- no LLM, no network."""

    def __init__(self, verdict: TriageVerdict, candidates: list[ProposedAction]) -> None:
        self._verdict = verdict
        self._candidates = candidates
        self.assess_calls = 0

    async def assess(self, finding: Finding) -> tuple[TriageVerdict, list[ProposedAction]]:
        self.assess_calls += 1
        return self._verdict, self._candidates


class RaisingTriageEngine:
    async def assess(self, finding: Finding):
        raise RuntimeError("triage exploded")


class FakePolicyEngine:
    """Returns a fixed disposition for every action, regardless of severity."""

    def __init__(self, disposition: str) -> None:
        self._disposition = disposition
        self.decide_calls: list[ProposedAction] = []

    def decide(self, action: ProposedAction, *, severity: float) -> PolicyDecision:
        self.decide_calls.append(action)
        return make_decision(action_class=action.action_class, disposition=self._disposition)


class FakeThreatIntel:
    """Records how many findings it was asked to enrich, and returns a fixed
    assessment with MITRE techniques."""

    def __init__(self) -> None:
        self.assess_calls: list[str] = []

    async def assess(self, finding: Finding):
        from kronagent.intel import MitreTechnique, ThreatIntelAssessment
        self.assess_calls.append(finding.finding_id)
        return ThreatIntelAssessment(
            finding_id=finding.finding_id, available=True,
            mitre_techniques=[MitreTechnique(technique_id="T1552.004",
                                             technique_name="Private Keys", tactic="Credential Access")],
            attack_lifecycle_stage="Exfiltration",
            intel_summary="scripted intel summary",
        )


def _finding(provider: str = "kubernetes", finding_id: str = "f-1", severity: float = 8.0) -> Finding:
    return Finding(provider=provider, finding_id=finding_id, finding_type="k8s:test", severity=severity)


def _verdict(finding_id: str, actionable: bool, severity: float = 8.0) -> TriageVerdict:
    return TriageVerdict(
        finding_id=finding_id, is_actionable_threat=actionable, threat_category="Test",
        confidence=0.9, severity=severity, justification="test justification",
    )


def _action(provider: str, action_class: ActionClass, target: str) -> ProposedAction:
    return ProposedAction(provider=provider, action_class=action_class, target=target, rationale="r")


def _queued(finding: Finding) -> tuple[QueuedFinding, Callable[[], int]]:
    """A QueuedFinding whose ack() call count is observable from the test."""
    state = {"acked": 0}

    async def ack() -> None:
        state["acked"] += 1

    return QueuedFinding(finding=finding, _ack=ack), lambda: state["acked"]


def _orchestrator(settings, triage, policy, *, approvals=None, threat_intel=None,
                  correlation=None, commander=None, forensics=None,
                  trajectory=None) -> tuple[Orchestrator, AuditLog]:
    audit = AuditLog(settings.audit_log_path)
    adapter = FakeContainmentAdapter(provider="kubernetes")
    containment = ContainmentExecutor(settings, {"kubernetes": adapter, "aws": adapter})
    orch = Orchestrator(settings, triage=triage, policy=policy, containment=containment,
                         audit=audit, approvals=approvals, threat_intel=threat_intel,
                         correlation=correlation, commander=commander, forensics=forensics,
                         trajectory=trajectory)
    return orch, audit


class FakeCorrelation:
    """Records what history it was handed for each finding, and reports a
    campaign linking to whatever prior finding_ids it saw."""

    def __init__(self) -> None:
        self.seen_prior: dict[str, list[str]] = {}

    async def assess(self, finding, prior):
        from kronagent.correlation import CorrelationAssessment
        prior_ids = [s.finding_id for s in prior]
        self.seen_prior[finding.finding_id] = prior_ids
        return CorrelationAssessment(
            finding_id=finding.finding_id,
            available=True,
            part_of_campaign=bool(prior_ids),
            related_finding_ids=prior_ids,
            correlation_summary="scripted correlation" if prior_ids else "",
        )


async def _drain(orch: Orchestrator, items: list[QueuedFinding]) -> None:
    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue()
    for item in items:
        await queue.put(item)
    done = asyncio.Event()
    done.set()  # everything is already enqueued
    await orch.run(queue, done)


async def test_non_actionable_finding_skips_policy_and_containment(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    policy = FakePolicyEngine(disposition="auto_execute")
    orch, _ = _orchestrator(settings, triage, policy)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert orch.processed == 1
    assert policy.decide_calls == []
    assert acked() == 1


async def test_actionable_with_no_candidates_still_completes(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[])
    policy = FakePolicyEngine(disposition="auto_execute")
    orch, _ = _orchestrator(settings, triage, policy)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert orch.processed == 1
    assert policy.decide_calls == []
    assert acked() == 1


async def test_requires_approval_creates_approval_request_with_correct_provider(settings) -> None:
    """End-to-end regression for the provider round-trip bug: an action
    proposed by the Kubernetes provider that requires approval must produce an
    ApprovalRequest whose provider/action_class/target survive to disk."""
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "payments-api-7f9c8d")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1
    assert pending[0].provider == "kubernetes"
    assert pending[0].action_class == ActionClass.ISOLATE_POD
    assert pending[0].target == "payments-api-7f9c8d"
    assert pending[0].to_proposed_action().provider == "kubernetes"
    assert acked() == 1


async def test_auto_execute_does_not_create_an_approval(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="auto_execute")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert approvals.list() == []
    assert acked() == 1


async def test_auto_execute_records_that_the_allowlist_entry_fired(settings) -> None:
    """An entry that never fires is standing authority with no benefit, so the
    review needs to know which ones actually get used. Recorded on the entry
    the autonomy came from, not the audit log — the containment record already
    covers the execution itself."""
    allowlist = AllowlistStore(settings.allowlist_store_path)
    audit = AuditLog(settings.audit_log_path)
    await allowlist.add(ActionClass.ISOLATE_POD, by="alice", reason="r", audit=audit)

    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine(disposition="auto_execute"))
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    entry = allowlist.list()[0]
    assert entry.fire_count == 1
    assert entry.last_fired_at is not None


async def test_approval_gated_execution_does_not_count_as_the_entry_firing(settings) -> None:
    """That action was authorized by a human, not by the entry. Counting it
    would let an unused promotion look load-bearing."""
    allowlist = AllowlistStore(settings.allowlist_store_path)
    audit = AuditLog(settings.audit_log_path)
    await allowlist.add(ActionClass.ISOLATE_POD, by="alice", reason="r", audit=audit)

    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine(disposition="requires_approval"),
                            approvals=ApprovalStore(settings.approval_store_path))
    await _drain(orch, [_queued(_finding(finding_id="f-1"))[0]])

    assert allowlist.list()[0].fire_count == 0


async def test_lapsed_allowlist_entry_is_swept_and_audited_during_a_run(settings) -> None:
    """The expiry lands in the audit chain from the running pipeline, not only
    when an operator happens to run the CLI — otherwise a deployment nobody
    logs into would enforce lapses silently, with no record of them."""
    allowlist = AllowlistStore(settings.allowlist_store_path)
    allowlist._write_all({"isolate_pod": {
        "action_class": "isolate_pod", "added_by": "alice", "reason": "expired promotion",
        "added_at": "2026-01-01T00:00:00+00:00", "expires_at": "2026-02-01T00:00:00+00:00",
    }})

    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, audit = _orchestrator(settings, triage, FakePolicyEngine(disposition="requires_approval"))
    await _drain(orch, [_queued(_finding(finding_id="f-1"))[0]])

    records = [json.loads(l)["record"] for l in open(audit._path) if l.strip()]
    expired = [r for r in records
               if r["stage"] == "governance" and r["payload"]["decision"] == "allowlist_expired"]
    assert len(expired) == 1
    assert expired[0]["payload"]["promotion_reason"] == "expired promotion"
    assert allowlist.list() == []


async def test_blocked_does_not_create_an_approval(settings) -> None:
    candidate = _action("kubernetes", ActionClass.DELETE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="blocked")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert approvals.list() == []
    assert acked() == 1


async def test_multiple_candidates_each_get_a_policy_decision(settings) -> None:
    candidates = [
        _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1"),
        _action("kubernetes", ActionClass.DELETE_POD, "pod-1"),
        _action("kubernetes", ActionClass.CORDON_NODE, "node-1"),
    ]
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=candidates)
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert len(policy.decide_calls) == 3
    assert len(approvals.list()) == 3
    assert acked() == 1


async def test_audit_records_every_stage_in_order(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    orch, audit = _orchestrator(settings, triage, policy)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    stages = [r["stage"] for r in records]
    assert stages == ["triage", "policy", "containment"]
    ok, broken = AuditLog.verify(settings.audit_log_path)
    assert ok is True and broken is None


async def test_error_in_triage_is_caught_audited_and_still_acked(settings) -> None:
    """A single bad finding must not crash the loop, and the message must
    still be acked (the finding was fully handled -- as an error -- not lost
    and not silently redelivered forever)."""
    orch, audit = _orchestrator(settings, RaisingTriageEngine(), FakePolicyEngine("auto_execute"))
    item, acked = _queued(_finding(finding_id="f-bad"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert any(r["stage"] == "error" for r in records)
    assert acked() == 1
    # processed is NOT incremented on error -- _handle raised before reaching
    # the increment, which is correct: this finding did not complete normally.
    assert orch.processed == 0


async def test_error_on_one_finding_does_not_block_the_next(settings) -> None:
    good_verdict = _verdict("f-good", actionable=False)

    class MixedTriage:
        def __init__(self) -> None:
            self.calls = 0

        async def assess(self, finding: Finding):
            self.calls += 1
            if finding.finding_id == "f-bad":
                raise RuntimeError("boom")
            return good_verdict, []

    orch, _ = _orchestrator(settings, MixedTriage(), FakePolicyEngine("auto_execute"))
    bad_item, bad_acked = _queued(_finding(finding_id="f-bad"))
    good_item, good_acked = _queued(_finding(finding_id="f-good"))

    await _drain(orch, [bad_item, good_item])

    assert bad_acked() == 1
    assert good_acked() == 1
    assert orch.processed == 1  # only the good finding completed successfully


async def test_threat_intel_enriches_actionable_finding_and_is_audited(settings) -> None:
    candidate = _action("aws", ActionClass.DISABLE_ACCESS_KEY, "AKIA1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals, threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    # Intel ran and was audited.
    assert intel.assess_calls == ["f-1"]
    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert any(r["stage"] == "threat_intel" for r in records)

    # And the MITRE context reached the approval request the human will see.
    pending = approvals.list(status="pending")
    assert pending[0].mitre_techniques == ["T1552.004"]
    assert pending[0].threat_intel_summary == "scripted intel summary"


async def test_threat_intel_not_called_for_non_actionable_finding(settings) -> None:
    """Cost discipline: intel must not run on noise. A non-actionable finding
    returns before the enrichment step."""
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"),
                            threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert intel.assess_calls == []  # never invoked


async def test_threat_intel_not_called_when_no_candidate_actions(settings) -> None:
    """Actionable but no containment action available -> no approval to enrich,
    so intel is skipped (same cost-scoping rationale)."""
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[])
    intel = FakeThreatIntel()
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"),
                            threat_intel=intel)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert intel.assess_calls == []


async def test_pipeline_works_without_a_threat_intel_agent(settings) -> None:
    """threat_intel is optional -- the orchestrator must run identically when
    it's None (backward compatible with pre-agent deployments)."""
    candidate = _action("aws", ActionClass.DISABLE_ACCESS_KEY, "AKIA1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, threat_intel=None)
    item, _acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1
    assert pending[0].mitre_techniques == []  # no intel, empty advisory fields
    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert not any(r["stage"] == "threat_intel" for r in records)


async def test_ack_failure_is_logged_not_raised(settings) -> None:
    triage = FakeTriageEngine(_verdict("f-1", actionable=False), candidates=[])
    orch, audit = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"))

    async def failing_ack() -> None:
        raise ConnectionError("SQS unreachable")

    item = QueuedFinding(finding=_finding(finding_id="f-1"), _ack=failing_ack)

    # Must not raise -- a failed ack means "will redeliver," not "crash the pipeline."
    await _drain(orch, [item])
    assert orch.processed == 1


# --------------------------------------------------------------------------- #
# Correlation agent integration
# --------------------------------------------------------------------------- #

async def test_correlation_memory_accumulates_across_findings(settings) -> None:
    """The second finding's correlation must see the first in its history --
    proving the orchestrator maintains the campaign window across findings,
    including a non-actionable first finding (a campaign's first stage)."""
    correlation = FakeCorrelation()
    # First finding non-actionable (noise), second actionable.
    class SeqTriage:
        async def assess(self, finding):
            actionable = finding.finding_id == "f-2"
            candidates = [_action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")] if actionable else []
            return _verdict(finding.finding_id, actionable=actionable), candidates

    orch, _ = _orchestrator(settings, SeqTriage(), FakePolicyEngine("requires_approval"),
                            correlation=correlation)
    i1, _ = _queued(_finding(finding_id="f-1"))
    i2, _ = _queued(_finding(finding_id="f-2"))

    await _drain(orch, [i1, i2])

    # f-2 was assessed with f-1 in its prior history.
    assert correlation.seen_prior["f-2"] == ["f-1"]


async def test_a_finding_judged_benign_is_withdrawn_from_later_history(settings) -> None:
    """The team recorded f-1 as benign. f-3 arrives afterwards and must be
    correlated against f-2 only: a false positive is not the first stage of
    anything."""
    from kronagent.outcomes import AnalystOutcome, OutcomeStore

    correlation = FakeCorrelation()

    class Quiet:
        async def assess(self, finding):
            return _verdict(finding.finding_id, actionable=False, severity=3.0), []

    orch, _ = _orchestrator(settings, Quiet(), FakePolicyEngine("requires_approval"), correlation=correlation)
    first, _ = _queued(_finding(finding_id="f-1", severity=3.0))
    second, _ = _queued(_finding(finding_id="f-2", severity=3.0))
    await _drain(orch, [first, second])
    OutcomeStore(settings.outcome_store_path).record(AnalystOutcome(
        finding_id="f-1", verdict="benign", team_action="no_action", recorded_by="ana"))

    class Loud(Quiet):
        async def assess(self, finding):
            return _verdict(finding.finding_id, actionable=True), [_action("kubernetes", ActionClass.ISOLATE_POD, "p")]

    orch._triage = Loud()
    third, _ = _queued(_finding(finding_id="f-3"))
    await _drain(orch, [third])
    assert correlation.seen_prior["f-3"] == ["f-2"]


async def test_correlation_threads_into_approval_context(settings) -> None:
    correlation = FakeCorrelation()
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")

    class SeqTriage:
        async def assess(self, finding):
            actionable = finding.finding_id == "f-2"
            return _verdict(finding.finding_id, actionable=actionable), \
                ([candidate] if actionable else [])

    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, SeqTriage(), FakePolicyEngine("requires_approval"),
                            approvals=approvals, correlation=correlation)
    i1, _ = _queued(_finding(finding_id="f-1"))
    i2, _ = _queued(_finding(finding_id="f-2"))

    await _drain(orch, [i1, i2])

    pending = approvals.list(status="pending")
    assert len(pending) == 1
    assert pending[0].related_finding_ids == ["f-1"]
    assert pending[0].correlation_summary == "scripted correlation"


async def test_correlation_stage_is_audited(settings) -> None:
    correlation = FakeCorrelation()
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, audit = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                                correlation=correlation)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    stages = [r["stage"] for r in records]
    assert "correlation" in stages
    assert AuditLog.verify(settings.audit_log_path)[0] is True


async def test_no_correlation_agent_leaves_pipeline_unchanged(settings) -> None:
    """Correlation is optional -- with no agent, no memory is maintained and no
    correlation stage is audited, but everything else works."""
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, audit = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"))
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert "correlation" not in [r["stage"] for r in records]
    assert orch.processed == 1


# --------------------------------------------------------------------------- #
# Incident Commander + Forensics integration
# --------------------------------------------------------------------------- #

class FakeCommander:
    """Records the specialist assessments it was handed, returns a fixed
    escalated assessment."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def assess(self, finding, verdict, intel, correlation):
        from kronagent.commander import IncidentAssessment
        self.calls.append((finding.finding_id, intel.available, correlation.available))
        return IncidentAssessment(
            finding_id=finding.finding_id, available=True,
            incident_narrative="scripted narrative", priority="P1",
            escalate_to_human_now=True, escalation_reason="scripted reason",
        )


class RecordingForensics:
    """Records the order in which it was invoked relative to containment."""

    def __init__(self, call_log: list[str]) -> None:
        self._log = call_log

    async def collect(self, finding, audit):
        from kronagent.forensics import EvidenceItem, ForensicsResult
        self._log.append("forensics")
        item = EvidenceItem(kind="aws.ebs.snapshot", target="i-1",
                            description="d", collection_calls=["c"]).with_custody_hash()
        return ForensicsResult(finding_id=finding.finding_id, provider=finding.provider,
                               items=[item])


async def test_commander_receives_all_specialist_assessments(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    commander = FakeCommander()
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            threat_intel=FakeThreatIntel(), correlation=FakeCorrelation(),
                            commander=commander)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert len(commander.calls) == 1
    fid, intel_available, _ = commander.calls[0]
    assert fid == "f-1"
    assert intel_available is True  # intel ran before the commander


async def test_commander_assessment_is_audited_and_threaded_into_approval(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, commander=FakeCommander())
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    records = [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]
    assert "command" in [r["stage"] for r in records]

    pending = approvals.list(status="pending")
    assert pending[0].incident_priority == "P1"
    assert pending[0].escalated is True
    assert pending[0].incident_narrative == "scripted narrative"


async def test_forensics_runs_before_containment(settings) -> None:
    """The ordering guarantee: evidence must be preserved before containment can
    alter or destroy the resource. If this inverts, forensics is worthless."""
    call_log: list[str] = []

    class OrderingAdapter(FakeContainmentAdapter):
        async def perform(self, action):
            call_log.append("containment")
            return await super().perform(action)

        def plan(self, action):
            call_log.append("containment")
            return super().plan(action)

    audit = AuditLog(settings.audit_log_path)
    adapter = OrderingAdapter(provider="kubernetes")
    containment = ContainmentExecutor(settings, {"kubernetes": adapter, "aws": adapter})
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])

    orch = Orchestrator(settings, triage=triage, policy=FakePolicyEngine("requires_approval"),
                        containment=containment, audit=audit,
                        forensics=RecordingForensics(call_log))
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert call_log, "neither stage ran"
    assert call_log[0] == "forensics", f"forensics must precede containment, got {call_log}"


async def test_evidence_kinds_are_threaded_into_approval_context(settings) -> None:
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, forensics=RecordingForensics([]))
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert pending[0].evidence_collected == ["aws.ebs.snapshot"]


async def test_pipeline_works_with_neither_new_agent(settings) -> None:
    """Both are optional -- absent them, no command/forensics stages are audited
    and everything else is unchanged."""
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"))
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    stages = [json.loads(l)["record"]["stage"] for l in open(settings.audit_log_path) if l.strip()]
    assert "command" not in stages
    assert "forensics" not in stages
    assert orch.processed == 1


# --------------------------------------------------------------------------- #
# Behavioral-trajectory guard wiring — the automatic kill switch, end to end
# through the orchestrator (not just the guard in isolation).
# --------------------------------------------------------------------------- #

def _finding_with_resource(finding_id: str, kind: str, resource_id: str) -> Finding:
    from kronagent.model import ResourceRef
    return Finding(
        provider="kubernetes", finding_id=finding_id, finding_type="k8s:test", severity=8.0,
        resources=[ResourceRef(kind=kind, id=resource_id, attributes={})],
    )


async def test_trajectory_scope_violation_blocks_before_policy(settings) -> None:
    """An action redirected onto a resource the finding never implicated is
    blocked by the guard BEFORE the policy engine ever sees it, and audited as a
    scope violation. This is the prompt-injection-to-wrong-resource defense."""
    from kronagent.trajectory import TrajectoryConfig, TrajectoryGuard

    guard = TrajectoryGuard(TrajectoryConfig(enforce_scope=True, max_scope_violations=1))
    # Finding implicates pod-1; the candidate targets a DIFFERENT pod.
    finding = _finding_with_resource("f-1", "k8s.pod", "pod-1")
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-victim-elsewhere")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="auto_execute")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals, trajectory=guard)
    item, acked = _queued(finding)

    await _drain(orch, [item])

    assert policy.decide_calls == []          # blocked before the policy engine
    assert approvals.list() == []             # never queued for a human either
    stages = [json.loads(l)["record"]["stage"] for l in open(settings.audit_log_path) if l.strip()]
    assert "trajectory_scope_violation" in stages
    assert "containment" not in stages
    assert acked() == 1                       # still fully handled + acked
    assert guard.halted                       # max_scope_violations=1 latched it


async def test_trajectory_in_scope_action_flows_normally(settings) -> None:
    """The guard must not interfere with legitimate, in-scope actions."""
    from kronagent.trajectory import TrajectoryConfig, TrajectoryGuard

    guard = TrajectoryGuard(TrajectoryConfig(enforce_scope=True))
    finding = _finding_with_resource("f-1", "k8s.pod", "pod-1")
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")  # in scope
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    policy = FakePolicyEngine(disposition="requires_approval")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals, trajectory=guard)
    item, _ = _queued(finding)

    await _drain(orch, [item])

    assert len(policy.decide_calls) == 1
    assert len(approvals.list()) == 1
    assert not guard.halted


async def test_trajectory_runaway_halt_blocks_subsequent_actions(settings) -> None:
    """Once the autonomous-execution ceiling is crossed the halt latches, and
    every later action is blocked at the top of the loop — before the policy
    engine — for the rest of the session."""
    from kronagent.trajectory import TrajectoryConfig, TrajectoryGuard

    # Ceiling of 2: the 3rd auto-execution trips the halt; the 4th is blocked
    # before policy. Scope enforcement off so it doesn't interfere.
    guard = TrajectoryGuard(TrajectoryConfig(enforce_scope=False, max_auto_executions=2, window_seconds=60))
    candidates = [_action("kubernetes", ActionClass.ISOLATE_POD, f"pod-{i}") for i in range(4)]
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=candidates)
    policy = FakePolicyEngine(disposition="auto_execute")
    orch, _ = _orchestrator(settings, triage, policy, trajectory=guard)
    item, acked = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    # Actions 1-3 reached the policy engine; the 3rd tripped the halt and the
    # 4th was blocked before policy ran.
    assert len(policy.decide_calls) == 3
    assert guard.halted
    stages = [json.loads(l)["record"]["stage"] for l in open(settings.audit_log_path) if l.strip()]
    assert "trajectory_halt" in stages
    assert acked() == 1


# --------------------------------------------------------------------------- #
# Triage override floor
#
# Triage's "not actionable" used to end the pipeline unconditionally. The model
# reaches that verdict by reading the finding, whose title and description can
# carry attacker-chosen text — so "known scanner noise, not actionable" in a
# finding could stop containment of a real attack with no approval request and
# no human ever seeing it. Above the floor a human now decides, and nothing the
# finding produces may auto-execute.
# --------------------------------------------------------------------------- #

def _floor_settings(settings, floor: float = 7.0):
    import dataclasses
    return dataclasses.replace(settings, triage_override_floor=floor)


def _audit_records(settings) -> list[dict]:
    return [json.loads(l)["record"] for l in open(settings.audit_log_path) if l.strip()]


async def test_a_model_cannot_silently_drop_a_high_severity_finding(settings) -> None:
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=False, severity=8.0),
                              candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=8.0))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1, "a high-severity finding the model dismissed vanished"
    assert "NOT actionable" in pending[0].policy_reason
    # policy_reason is deterministic: the model's own words must not be in it.
    assert "test justification" not in pending[0].policy_reason


async def test_an_overridden_finding_never_auto_executes(settings) -> None:
    """The load-bearing half. Allowlisted, reversible, single-resource — policy
    says auto-execute — and it still waits for a human, because the only reason
    it reached policy at all is that a model's dismissal was overruled."""
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=False, severity=9.0),
                              candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("auto_execute"),
                            approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=9.0))

    await _drain(orch, [item])

    records = _audit_records(settings)
    contained = [r for r in records if r["stage"] == "containment"]
    assert contained and all(r["payload"]["executed"] is False for r in contained)
    assert all(r["payload"]["decision"]["disposition"] == "requires_approval"
               for r in records if r["stage"] == "policy")
    assert len(approvals.list(status="pending")) == 1


async def test_below_the_floor_triage_still_filters_noise(settings) -> None:
    """The floor must not turn every dismissal into an approval request. Below
    it the verdict stands, and policy is never consulted."""
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=False, severity=5.0),
                              candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    policy = FakePolicyEngine("auto_execute")
    orch, _ = _orchestrator(settings, triage, policy, approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=5.0))

    await _drain(orch, [item])

    assert policy.decide_calls == []
    assert approvals.list(status="pending") == []


async def test_the_override_is_audited(settings) -> None:
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=False, severity=8.0),
                              candidates=[candidate])
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=ApprovalStore(settings.approval_store_path))
    item, _ = _queued(_finding(finding_id="f-1", severity=8.0))

    await _drain(orch, [item])

    overrides = [r for r in _audit_records(settings) if r["stage"] == "triage_override"]
    assert len(overrides) == 1
    assert overrides[0]["payload"]["severity"] == 8.0
    assert overrides[0]["payload"]["override_floor"] == 7.0


async def test_a_policy_block_still_wins_over_the_override(settings) -> None:
    """The override widens what a human sees; it never widens what may run. A
    kill switch or containment threshold block stays a block."""
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=False, severity=8.0),
                              candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("blocked"),
                            approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=8.0))

    await _drain(orch, [item])

    assert approvals.list(status="pending") == []
    assert all(r["payload"]["decision"]["disposition"] == "blocked"
               for r in _audit_records(settings) if r["stage"] == "policy")


def test_override_floor_configuration() -> None:
    from kronagent.config import Settings

    assert Settings().triage_override_floor == 7.0
    assert any("TRIAGE_OVERRIDE_FLOOR" in e for e in
               Settings(triage_override_floor=11.0).validate())
    below = Settings(triage_override_floor=3.0, min_severity_for_containment=4.0).validate()
    assert any("no effect" in e for e in below), below


def test_override_floor_does_not_pile_onto_an_invalid_threshold() -> None:
    """One bad value, one error. An out-of-range MIN_SEVERITY is the thing to
    fix; reporting the floor as 'below' it too would bury that."""
    from kronagent.config import Settings

    errors = Settings(min_severity_for_containment=15.0).validate()
    assert any("KRONAGENT_MIN_SEVERITY" in e for e in errors)
    assert not any("TRIAGE_OVERRIDE_FLOOR" in e for e in errors), errors


# --------------------------------------------------------------------------- #
# Enrichment fan-out
#
# Threat intel and correlation are independent, so they run concurrently: one
# model round-trip of wall-clock per actionable finding instead of two. Three
# properties matter, and each is pinned below: they really do overlap, the audit
# log records them in a fixed order regardless of which finishes first, and a
# failing agent cancels its sibling while surfacing its own error.
# --------------------------------------------------------------------------- #

class _Rendezvous:
    """Tells each agent whether the other had started before it could finish.

    Run sequentially, the first agent waits out the timeout alone and reports
    False. Run concurrently, both arrive and both report True.
    """

    def __init__(self) -> None:
        self.started: set[str] = set()
        self.both = asyncio.Event()

    async def enter(self, name: str) -> bool:
        self.started.add(name)
        if len(self.started) == 2:
            self.both.set()
        try:
            await asyncio.wait_for(self.both.wait(), timeout=1.0)
            return True
        except asyncio.TimeoutError:
            return False


class _MeetingIntel(FakeThreatIntel):
    def __init__(self, rendezvous: _Rendezvous) -> None:
        super().__init__()
        self._rendezvous = rendezvous
        self.overlapped: bool | None = None

    async def assess(self, finding):
        self.overlapped = await self._rendezvous.enter("intel")
        return await super().assess(finding)


class _MeetingCorrelation(FakeCorrelation):
    def __init__(self, rendezvous: _Rendezvous) -> None:
        super().__init__()
        self._rendezvous = rendezvous
        self.overlapped: bool | None = None

    async def assess(self, finding, prior):
        self.overlapped = await self._rendezvous.enter("correlation")
        return await super().assess(finding, prior)


async def test_intel_and_correlation_run_concurrently(settings) -> None:
    rendezvous = _Rendezvous()
    intel, correlation = _MeetingIntel(rendezvous), _MeetingCorrelation(rendezvous)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, threat_intel=intel, correlation=correlation)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    assert intel.overlapped is True and correlation.overlapped is True, (
        "intel and correlation did not overlap — they ran one after the other")
    # Concurrency must not cost the join: both results still reach the request.
    assert approvals.list(status="pending")[0].threat_intel_summary == "scripted intel summary"


class _SlowIntel(FakeThreatIntel):
    async def assess(self, finding):
        await asyncio.sleep(0.05)
        return await super().assess(finding)


async def test_enrichment_is_audited_in_a_fixed_order_whatever_finishes_first(settings) -> None:
    """Correlation answers first here. The audit log is a hash chain, and a
    chain whose record order depends on provider latency cannot be reproduced
    by two identical runs — so intel is still recorded first."""
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=ApprovalStore(settings.approval_store_path),
                            threat_intel=_SlowIntel(), correlation=FakeCorrelation())
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    stages = [r["stage"] for r in _audit_records(settings)]
    assert stages.index("threat_intel") < stages.index("correlation"), stages


class _ExplodingIntel:
    async def assess(self, finding):
        await asyncio.sleep(0.01)
        raise RuntimeError("intel agent exploded")


class _SlowCorrelation(FakeCorrelation):
    def __init__(self) -> None:
        super().__init__()
        self.cancelled = False
        self.finished = False

    async def assess(self, finding, prior):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        self.finished = True
        return await super().assess(finding, prior)


async def test_a_failing_enrichment_agent_cancels_its_sibling(settings, capsys) -> None:
    """Both real agents degrade instead of raising, so this guards anything that
    does not. With gather() the failure would return while correlation kept
    running unattended; a TaskGroup cancels it. And the worker must log the
    agent's real error, not "unhandled errors in a TaskGroup"."""
    correlation = _SlowCorrelation()
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, triage, FakePolicyEngine("requires_approval"),
                            approvals=approvals, threat_intel=_ExplodingIntel(),
                            correlation=correlation)
    item, _ = _queued(_finding(finding_id="f-1"))

    await _drain(orch, [item])

    out = capsys.readouterr().out
    assert correlation.cancelled and not correlation.finished
    assert "RuntimeError: intel agent exploded" in out
    assert "ExceptionGroup" not in out
    assert approvals.list(status="pending") == []


# --------------------------------------------------------------------------- #
# Contested dismissals
#
# The floor only protects high-severity findings. Below it, a model that read
# "this is the approved penetration test" in a description dropped the finding.
# Triage now marks a dismissal contested when the structured fields alone read
# as a threat, and a contested finding reaches a person at any severity.
# --------------------------------------------------------------------------- #

async def test_a_contested_dismissal_below_the_floor_still_reaches_a_person(settings) -> None:
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    verdict = _verdict("f-1", actionable=False, severity=5.0).model_copy(update={"contested": True})
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, FakeTriageEngine(verdict, candidates=[candidate]),
                            FakePolicyEngine("auto_execute"), approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=5.0))

    await _drain(orch, [item])

    pending = approvals.list(status="pending")
    assert len(pending) == 1, "a finding the text talked the model out of was dropped"
    assert "free text is what changed the verdict" in pending[0].policy_reason
    records = _audit_records(settings)
    # Policy said auto-execute; a contested finding still waits for a person.
    assert all(r["payload"]["executed"] is False for r in records if r["stage"] == "containment")
    (override,) = [r for r in records if r["stage"] == "triage_override"]
    assert override["payload"]["cause"] == "contested_by_structured_fields"


async def test_an_uncontested_dismissal_below_the_floor_is_still_noise(settings) -> None:
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    approvals = ApprovalStore(settings.approval_store_path)
    orch, _ = _orchestrator(settings, FakeTriageEngine(_verdict("f-1", actionable=False, severity=5.0),
                                                       candidates=[candidate]),
                            FakePolicyEngine("requires_approval"), approvals=approvals)
    item, _ = _queued(_finding(finding_id="f-1", severity=5.0))

    await _drain(orch, [item])

    assert approvals.list(status="pending") == []
    assert not [r for r in _audit_records(settings) if r["stage"] == "triage_override"]


async def test_the_floor_is_named_as_the_cause_when_it_is_the_cause(settings) -> None:
    settings = _floor_settings(settings)
    candidate = _action("kubernetes", ActionClass.ISOLATE_POD, "pod-1")
    orch, _ = _orchestrator(settings, FakeTriageEngine(_verdict("f-1", actionable=False, severity=8.0),
                                                       candidates=[candidate]),
                            FakePolicyEngine("requires_approval"),
                            approvals=ApprovalStore(settings.approval_store_path))
    item, _ = _queued(_finding(finding_id="f-1", severity=8.0))

    await _drain(orch, [item])

    (override,) = [r for r in _audit_records(settings) if r["stage"] == "triage_override"]
    assert override["payload"]["cause"] == "severity_floor"
