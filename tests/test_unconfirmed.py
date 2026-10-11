"""
Autonomous actions nobody has confirmed: found, dated, made loud, never released.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from kronagent.audit import AuditLog
from kronagent.digest import build_digest, render_markdown
from kronagent.outcomes import AnalystOutcome, OutcomeStore
from kronagent.schemas import AuditRecord
from kronagent.shadow import calls_from_audit
from kronagent.unconfirmed import render_text, unconfirmed_actions

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(hours=24)


def _acted(fid: str, hours_ago: float | None, *, disposition: str = "auto_execute", executed: bool = True,
           action: str = "disable_access_key") -> list[dict]:
    ts = "" if hours_ago is None else (NOW - timedelta(hours=hours_ago)).isoformat()
    return [
        {"ts": ts, "finding_id": fid, "stage": "triage", "payload": {"is_actionable_threat": True, "severity": 8.0}},
        {"ts": ts, "finding_id": fid, "stage": "policy", "payload": {
            "action": {"action_class": action, "provider": "aws", "target": "x"},
            "decision": {"disposition": disposition}}},
        {"ts": ts, "finding_id": fid, "stage": "containment", "payload": {
            "action_class": action, "target": "x", "executed": executed, "dry_run": not executed}},
    ]


def _outcome(fid: str, verdict: str = "malicious", action: str = "contained") -> AnalystOutcome:
    return AnalystOutcome(finding_id=fid, verdict=verdict, team_action=action, recorded_by="ana")


def _pending(records: list[dict], outcomes: list[AnalystOutcome] = (), **kw):
    return unconfirmed_actions(calls_from_audit(records), list(outcomes), now=NOW,
                               confirm_within=kw.pop("within", DAY), **kw)


def test_an_unattended_action_with_no_outcome_is_pending_and_overdue_after_the_window() -> None:
    fresh, stale = _pending(_acted("fresh", 2) + _acted("stale", 30))[::-1]
    assert (fresh.finding_id, fresh.overdue, fresh.age_hours) == ("fresh", False, 2.0)
    assert (stale.finding_id, stale.overdue, stale.executed) == ("stale", True, True)
    assert stale.action_classes == ["disable_access_key"]


def test_the_oldest_comes_first_and_an_undatable_one_before_that() -> None:
    order = [u.finding_id for u in _pending(_acted("b", 5) + _acted("undated", None) + _acted("a", 50))]
    assert order == ["undated", "a", "b"]
    assert _pending(_acted("undated", None))[0].overdue is True


def test_any_conclusive_outcome_confirms_and_an_inconclusive_one_does_not() -> None:
    records = _acted("right", 30) + _acted("wrong", 30) + _acted("unsure", 30)
    left = _pending(records, [_outcome("right"), _outcome("wrong", "benign", "no_action"),
                              _outcome("unsure", "inconclusive", "no_action")])
    assert [u.finding_id for u in left] == ["unsure"] and left[0].looked_at_inconclusive
    assert "still needs a verdict" in render_text(left, "24h")


def test_an_action_a_person_approved_is_not_waiting_for_anyone() -> None:
    assert _pending(_acted("approved", 30, disposition="requires_approval")) == []


def test_in_dry_run_nothing_ran_so_nothing_is_pending_unless_asked() -> None:
    records = _acted("shadow", 30, executed=False)
    assert _pending(records) == []
    (would,) = _pending(records, include_dry_run=True)
    assert would.executed is False and "would have run (dry-run)" in render_text([would], "24h")


def test_the_report_says_nothing_is_released() -> None:
    text = render_text(_pending(_acted("stale", 30)), "24h")
    assert "OVERDUE" in text and "Nothing here has been released, and nothing will be." in text
    assert render_text([], "24h") == "No autonomous action is waiting for an outcome."


def test_the_digest_leads_with_overdue_actions_from_any_week() -> None:
    old = _acted("three-weeks", 24 * 21)                       # far outside the digest's 7-day window
    digest = build_digest("default", old, [], [], now=NOW, days=7, dry_run=False, confirm_within="24h")
    assert [u.finding_id for u in digest.unconfirmed] == ["three-weeks"]
    alert = next(a for a in digest.alerts if "no recorded outcome" in a)
    assert "1 autonomous action(s)" in alert and "Nothing has been released" in alert
    assert "`three-weeks` disable_access_key" in render_markdown(digest)
    confirmed = build_digest("default", old, [], [_outcome("three-weeks")], now=NOW, days=7, dry_run=False)
    assert confirmed.unconfirmed == [] and not any("no recorded outcome" in a for a in confirmed.alerts)


def _cli(tmp_path: Path, *args: str, within: str | None = None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
           "KRONAGENT_OUTCOME_PATH": str(tmp_path / "outcomes.json"),
           "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
           "KRONAGENT_CONNECTION_PATH": str(tmp_path / "connections.json"),
           "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": ""}
    if within:
        env["KRONAGENT_CONFIRM_WITHIN"] = within
    return subprocess.run([sys.executable, "outcome.py", *args], cwd=REPO, capture_output=True, text=True, env=env)


def test_cli_pending_exits_3_only_when_something_is_overdue_and_recording_clears_it(tmp_path: Path) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for rec in _acted("f-live", 0):           # the audit log stamps its own time: just now
        asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"],
                                           payload=rec["payload"])))

    waiting = _cli(tmp_path, "pending")
    assert waiting.returncode == 0 and "f-live" in waiting.stdout and "OVERDUE" not in waiting.stdout

    time.sleep(1.5)                           # durations must be positive, so let a second pass
    overdue = _cli(tmp_path, "pending", "--json", within="1s")
    assert overdue.returncode == 3 and json.loads(overdue.stdout)[0]["overdue"] is True
    assert _cli(tmp_path, "pending", "--older-than", "nonsense").returncode == 2

    OutcomeStore(str(tmp_path / "outcomes.json")).record(_outcome("f-live"))
    cleared = _cli(tmp_path, "pending", within="1s")
    assert cleared.returncode == 0 and "No autonomous action is waiting" in cleared.stdout
