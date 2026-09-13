"""
Pinned classification — an entry is a decision about an action as it was
classified, and does not survive that classification changing.

The case that matters is the quiet one. `promote.py add` accepts a class the
policy table calls destructive: the promotion is recorded but inert, because the
ceiling routes that class to approval anyway. Before pinning, the day someone
relaxed that class in the table, the old entry went live — unattended execution
authorised by a promotion nobody made about the action as it now stands.

What is pinned here:
  * add, renewal and seeding all record the current classification;
  * the gate refuses an entry whose action has been reclassified, in either
    direction, with no sweep in the loop;
  * the sweep latches it once; reverting the table does not undo it, a
    reassignment does not lift it, and only a renewal does;
  * entries from before pinning are not refused, but review says they are
    unpinned;
  * every field of the classification is pinned, including ones added later.
"""

from __future__ import annotations

import pytest

from kronagent import classification
from kronagent.allowlist import SUSPENDED_RECLASSIFIED, AllowlistStore
from kronagent.audit import AuditLog
from kronagent.classification import action_properties, pinned_classification
from kronagent.config import Settings
from kronagent.policy import PolicyEngine
from kronagent.schemas import ActionClass, BlastRadius, ProposedAction


@pytest.fixture
def store(tmp_path) -> AllowlistStore:
    return AllowlistStore(str(tmp_path / "allowlist.json"))


def _reclassify(monkeypatch, action_class: ActionClass, **changes) -> None:
    monkeypatch.setitem(classification._ACTION_PROPERTIES, action_class,
                        {**classification._ACTION_PROPERTIES[action_class], **changes})


def _suspended_records(audit: AuditLog) -> list[dict]:
    return [r for r in audit.records()
            if r.get("stage") == "governance"
            and r["payload"].get("decision") == "allowlist_suspended"]


def test_every_classification_field_is_pinned() -> None:
    """A field added to the table later must be pinned too, or a change to it
    would slip past the comparison."""
    for action_class in ActionClass:
        assert set(pinned_classification(action_class)) == set(action_properties(action_class))


async def test_add_and_seed_pin_the_current_classification(store, audit_log, tmp_path) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log)
    assert store.list()[0].classification == pinned_classification(ActionClass.BLOCK_IP)

    seeded = AllowlistStore(str(tmp_path / "seeded.json"),
                            seed=frozenset({"cordon_node", "retired_action"}))
    pins = {e.action_class: e.classification for e in seeded.list()}
    assert pins["cordon_node"] == pinned_classification(ActionClass.CORDON_NODE)
    assert pins["retired_action"] is None


def _settings(tmp_path) -> Settings:
    return Settings(dry_run=True, allowlist_store_path=str(tmp_path / "allowlist.json"),
                    audit_log_path=str(tmp_path / "audit.jsonl"),
                    approval_store_path=str(tmp_path / "approvals.json"))


def _action(action_class: ActionClass) -> ProposedAction:
    return ProposedAction(provider="aws", action_class=action_class, target="t", rationale="r")


async def test_an_inert_promotion_does_not_go_live_when_the_table_relaxes(
        tmp_path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    store = AllowlistStore(settings.allowlist_store_path)
    engine = PolicyEngine(settings, store)
    await store.add(ActionClass.REVOKE_ROLE_SESSIONS, by="alice", reason="r",
                    audit=AuditLog(settings.audit_log_path))
    assert engine.decide(_action(ActionClass.REVOKE_ROLE_SESSIONS),
                         severity=8.0).disposition == "requires_approval"

    _reclassify(monkeypatch, ActionClass.REVOKE_ROLE_SESSIONS, destructive=False)
    assert engine.is_auto_eligible(ActionClass.REVOKE_ROLE_SESSIONS) is True

    decision = engine.decide(_action(ActionClass.REVOKE_ROLE_SESSIONS), severity=8.0)
    assert decision.disposition == "requires_approval"
    assert "reclassified" in decision.reason and "destructive" in decision.reason


async def test_a_tightened_class_is_refused_by_the_entry_as_well_as_the_ceiling(
        store, audit_log, monkeypatch) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log)
    _reclassify(monkeypatch, ActionClass.BLOCK_IP, blast_radius=BlastRadius.ACCOUNT)
    allowed, why = store.evaluate(ActionClass.BLOCK_IP)
    assert allowed is False
    assert "blast_radius 'single_resource' → 'account'" in why


async def test_the_sweep_latches_once_and_reverting_the_table_does_not_undo_it(
        store, audit_log, monkeypatch) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="quiet for 30d", audit=audit_log)
    original = dict(classification._ACTION_PROPERTIES[ActionClass.BLOCK_IP])
    _reclassify(monkeypatch, ActionClass.BLOCK_IP, reversible=False)

    swept = await store.suspend_reclassified(audit=audit_log)
    assert [e.action_class for e, _ in swept] == ["block_ip"]
    assert await store.suspend_reclassified(audit=audit_log) == []

    records = _suspended_records(audit_log)
    assert len(records) == 1
    payload = records[0]["payload"]
    assert payload["trigger"] == SUSPENDED_RECLASSIFIED
    assert payload["pinned_classification"]["reversible"] is True
    assert payload["current_classification"]["reversible"] is False
    assert payload["promotion_reason"] == "quiet for 30d"

    monkeypatch.setitem(classification._ACTION_PROPERTIES, ActionClass.BLOCK_IP, original)
    assert store.is_allowed(ActionClass.BLOCK_IP) is False
    assert store.active() == []


async def test_a_reassignment_does_not_lift_it_and_a_renewal_does(
        store, audit_log, monkeypatch) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log)
    _reclassify(monkeypatch, ActionClass.BLOCK_IP, reversible=False)
    await store.suspend_reclassified(audit=audit_log)

    await store.set_owner(ActionClass.BLOCK_IP, owner="dana", by="alice", reason="r",
                          audit=audit_log)
    assert store.list()[0].is_suspended is True

    # The renewal is a decision about the action as it is classified now.
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="still applies", audit=audit_log)
    entry = store.list()[0]
    assert entry.is_suspended is False
    assert entry.classification["reversible"] is False
    assert entry.classification_drift() is None


async def test_an_entry_from_before_pinning_is_not_refused_but_is_flagged(
        store, tmp_path, monkeypatch) -> None:
    store._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    _reclassify(monkeypatch, ActionClass.BLOCK_IP, reversible=False)
    assert store.list()[0].classification_drift() is None
    assert store.is_allowed(ActionClass.BLOCK_IP) is True   # the ceiling still refuses it


def test_review_flags_an_unpinned_entry(tmp_path) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    AllowlistStore(str(tmp_path / "allowlist.json"))._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(repo / "promote.py"), "review", "--by", "carol"],
        capture_output=True, text=True, cwd=str(repo),
        env={**os.environ, "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl")},
    )
    assert result.returncode == 0, result.stderr
    assert "classification not pinned" in result.stdout


def test_an_unknown_action_class_neither_drifts_nor_breaks_the_sweep(store, audit_log) -> None:
    import asyncio
    store._write_all({"retired_action": {
        "action_class": "retired_action", "added_by": "alice", "reason": "r",
        "classification": {"reversible": True, "blast_radius": "single_resource",
                           "destructive": False},
    }})
    assert store.list()[0].classification_drift() is None
    assert asyncio.run(store.suspend_reclassified(audit=audit_log)) == []


async def test_the_pipeline_records_the_suspension_before_the_decision(
        tmp_path, monkeypatch) -> None:
    from kronagent.containment import ContainmentExecutor
    from kronagent.orchestrator import Orchestrator

    from .conftest import FakeContainmentAdapter
    from .test_orchestrator import FakeTriageEngine, _drain, _finding, _queued, _verdict

    settings = _settings(tmp_path)
    audit = AuditLog(settings.audit_log_path)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="alice", reason="r", audit=audit)
    _reclassify(monkeypatch, ActionClass.ISOLATE_POD, destructive=True)

    candidate = ProposedAction(provider="kubernetes", action_class=ActionClass.ISOLATE_POD,
                               target="pod-1", rationale="r")
    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[candidate])
    adapter = FakeContainmentAdapter(provider="kubernetes")
    orch = Orchestrator(settings, triage=triage, policy=PolicyEngine(settings, store),
                        containment=ContainmentExecutor(settings, {"kubernetes": adapter}),
                        audit=audit)
    await _drain(orch, [_queued(_finding(finding_id="f-1"))[0]])

    records = audit.records()
    suspended_at = next(i for i, r in enumerate(records)
                        if r["payload"].get("decision") == "allowlist_suspended")
    policy_at = next(i for i, r in enumerate(records) if r["stage"] == "policy")
    assert suspended_at < policy_at
    assert records[suspended_at]["payload"]["trigger"] == SUSPENDED_RECLASSIFIED
