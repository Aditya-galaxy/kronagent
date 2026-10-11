"""
Promotion evidence: a bound on how often an action class would have been wrong,
and the ways it must refuse to flatter itself.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.audit import AuditLog
from kronagent.evidence import build_evidence, render_text
from kronagent.outcomes import AnalystOutcome, OutcomeStore
from kronagent.schemas import AuditRecord
from kronagent.shadow import calls_from_audit
from kronagent.stats import binomial_upper_bound, clean_trials_needed

REPO = Path(__file__).resolve().parent.parent


# --- the statistics ----------------------------------------------------------

def test_no_failures_is_the_rule_of_three() -> None:
    assert binomial_upper_bound(0, 20) == pytest.approx(1 - 0.05 ** (1 / 20))      # 13.9%
    assert binomial_upper_bound(0, 59) < 0.05 < binomial_upper_bound(0, 58)
    assert clean_trials_needed(0.05) == 59 and clean_trials_needed(0.01) == 299


def test_the_bound_matches_known_exact_values_and_moves_the_right_way() -> None:
    assert binomial_upper_bound(3, 100) == pytest.approx(0.0757, abs=0.0005)
    assert binomial_upper_bound(1, 59) == pytest.approx(0.0779, abs=0.0005)
    assert binomial_upper_bound(1, 59) > binomial_upper_bound(0, 59)                # a failure costs
    assert binomial_upper_bound(2, 200) < binomial_upper_bound(2, 100)              # more evidence helps
    assert binomial_upper_bound(0, 59, 0.99) > binomial_upper_bound(0, 59, 0.95)    # more confidence costs


def test_nothing_scored_shows_nothing() -> None:
    assert binomial_upper_bound(0, 0) == 1.0 and binomial_upper_bound(5, 5) == 1.0
    with pytest.raises(ValueError):
        binomial_upper_bound(6, 5)


# --- what counts -------------------------------------------------------------

def _finding(fid: str, *, actionable: bool = True, action: str = "block_ip", provider: str = "aws",
             disposition: str = "requires_approval", override: bool = False, ts: str = "") -> list[dict]:
    recs = [{"ts": ts or "2026-09-01T00:00:00Z", "finding_id": fid, "stage": "triage",
             "payload": {"is_actionable_threat": actionable, "severity": 8.0}}]
    if override:
        recs.append({"finding_id": fid, "stage": "triage_override", "payload": {}})
    recs.append({"finding_id": fid, "stage": "policy", "payload": {
        "action": {"action_class": action, "provider": provider, "target": "x"},
        "decision": {"disposition": disposition}}})
    return recs


def _outcome(fid: str, verdict: str = "malicious", action: str = "contained", revision: int = 1) -> AnalystOutcome:
    return AnalystOutcome(finding_id=fid, verdict=verdict, team_action=action, recorded_by="ana",
                          revision=revision)


def _evidence(records: list[dict], outcomes: list[AnalystOutcome], **kw):
    return build_evidence(calls_from_audit(records), outcomes, kw.pop("action_class", "block_ip"), **kw)


def test_a_clean_record_gives_a_bound_not_a_guarantee() -> None:
    records = [r for i in range(20) for r in _finding(f"f{i}")]
    ev = _evidence(records, [_outcome(f"f{i}") for i in range(20)], max_error=0.05)
    assert (ev.planned, ev.scored, ev.warranted, ev.unwarranted) == (20, 20, 20, 0)
    assert ev.error_upper_bound == pytest.approx(0.139, abs=0.001)
    assert ev.meets_bar is False and ev.clean_findings_still_needed == 39       # 59 in all
    assert "fewer than 13.9%" in ev.statement()


def test_unwarranted_is_benign_or_not_contained_and_every_one_is_listed() -> None:
    records = [r for f in ("a", "b", "c", "d") for r in _finding(f)]
    ev = _evidence(records, [_outcome("a"), _outcome("b", verdict="benign"),
                             _outcome("c", action="no_action"), _outcome("d", "benign", "no_action")])
    assert (ev.warranted, ev.unwarranted) == (1, 3)
    assert [u.finding_id for u in ev.unwarranted_findings] == ["b", "c", "d"]
    text = render_text(ev)
    assert all(f"    {f}  severity" in text for f in ("b", "c", "d"))


def test_unlabeled_and_inconclusive_are_left_out_never_counted_as_agreement() -> None:
    records = [r for f in ("a", "b", "c") for r in _finding(f)]
    ev = _evidence(records, [_outcome("a"), _outcome("b", verdict="inconclusive")])
    assert (ev.planned, ev.scored, ev.unlabeled, ev.inconclusive) == (3, 1, 1, 1)
    assert ev.error_upper_bound == pytest.approx(0.95)             # one scored finding shows very little


def test_only_findings_that_would_have_run_unattended_count() -> None:
    records = (_finding("dismissed", actionable=False, override=True)       # forced to a person regardless
               + _finding("other-class", action="isolate_pod", provider="kubernetes")
               + _finding("blocked", disposition="blocked")
               + _finding("counts"))
    outcomes = [_outcome(f, "benign", "no_action") for f in ("dismissed", "other-class", "blocked")]
    ev = _evidence(records, [*outcomes, _outcome("counts")])
    assert (ev.planned, ev.scored, ev.unwarranted) == (1, 1, 0)


def test_evidence_is_scoped_to_the_providers_the_promotion_covers() -> None:
    records = _finding("aws-1") + _finding("cf-1", provider="cloudflare")
    outcomes = [_outcome("aws-1"), _outcome("cf-1", "benign", "no_action")]
    assert _evidence(records, outcomes, providers=["aws"]).unwarranted == 0
    assert _evidence(records, outcomes, providers=["cloudflare"]).unwarranted == 1
    assert _evidence(records, outcomes).scored == 2


def test_one_bad_call_costs_many_clean_ones() -> None:
    records = [r for i in range(59) for r in _finding(f"f{i}")]
    clean = _evidence(records, [_outcome(f"f{i}") for i in range(59)], max_error=0.05)
    one_bad = _evidence(records, [_outcome("f0", "benign", "no_action"),
                                  *[_outcome(f"f{i}") for i in range(1, 59)]], max_error=0.05)
    assert clean.meets_bar is True and clean.clean_findings_still_needed is None
    assert one_bad.meets_bar is False
    more = one_bad.clean_findings_still_needed
    assert binomial_upper_bound(1, 59 + more) <= 0.05 < binomial_upper_bound(1, 59 + more - 1)
    assert more > 30


def test_since_drops_older_findings_and_revisions_are_reported() -> None:
    records = _finding("old", ts="2026-01-01T00:00:00Z") + _finding("new", ts="2026-09-01T00:00:00Z")
    ev = _evidence(records, [_outcome("old", "benign", "no_action"), _outcome("new", revision=2)],
                   since="2026-06-01T00:00:00Z")
    assert (ev.scored, ev.unwarranted, ev.revised_outcomes) == (1, 0, 1)
    assert "revised" in render_text(ev)


# --- the CLI -----------------------------------------------------------------

def _seed(tmp_path: Path, clean: int, bad: int = 0) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    store = OutcomeStore(str(tmp_path / "outcomes.json"))
    for i in range(clean + bad):
        for rec in _finding(f"f{i}", action="disable_access_key"):
            asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"],
                                               payload=rec["payload"])))
        store.record(_outcome(f"f{i}", "benign", "no_action") if i < bad else _outcome(f"f{i}"))


def _promote(tmp_path: Path, *args: str, max_error: str | None = None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
           "KRONAGENT_OUTCOME_PATH": str(tmp_path / "outcomes.json"),
           "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
           "KRONAGENT_CONNECTION_PATH": str(tmp_path / "connections.json"),
           "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": ""}
    if max_error:
        env["KRONAGENT_PROMOTION_MAX_ERROR"] = max_error
    return subprocess.run([sys.executable, "promote.py", *args], cwd=REPO, capture_output=True, text=True, env=env)


def test_cli_evidence_prints_the_bound_and_gates_on_the_bar(tmp_path: Path) -> None:
    _seed(tmp_path, clean=20)
    shown = _promote(tmp_path, "evidence", "disable_access_key")
    assert shown.returncode == 0 and "fewer than 13.9%" in shown.stdout
    gated = _promote(tmp_path, "evidence", "disable_access_key", "--json", max_error="0.05")
    assert gated.returncode == 3
    assert json.loads(gated.stdout)["clean_findings_still_needed"] == 39


def test_cli_add_records_the_evidence_and_does_not_enforce_without_a_bar(tmp_path: Path) -> None:
    _seed(tmp_path, clean=5)
    done = _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "trial")
    assert done.returncode == 0, done.stderr
    assert "Evidence: With 95% confidence, fewer than 45.1%" in done.stdout
    entry = json.loads((tmp_path / "allowlist.json").read_text())["disable_access_key"]
    assert entry["evidence"]["scored"] == 5 and entry["evidence_override"] is None


def test_cli_add_refuses_below_the_bar_and_an_override_is_recorded(tmp_path: Path) -> None:
    _seed(tmp_path, clean=20, bad=1)
    refused = _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "trial",
                       max_error="0.05")
    assert refused.returncode == 2 and "REFUSED" in refused.stderr and "f0  severity" in refused.stderr
    assert not (tmp_path / "allowlist.json").exists() or \
        "disable_access_key" not in json.loads((tmp_path / "allowlist.json").read_text())

    forced = _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "trial",
                      "--override-evidence", "pilot with the customer watching", max_error="0.05")
    assert forced.returncode == 0, forced.stderr
    assert "WITHOUT meeting the bar" in forced.stdout
    entry = json.loads((tmp_path / "allowlist.json").read_text())["disable_access_key"]
    assert entry["evidence_override"] == "pilot with the customer watching"
    governance = [json.loads(line)["record"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()
                  if '"allowlist_add"' in line]
    assert governance[-1]["payload"]["evidence_override"] == "pilot with the customer watching"
    assert governance[-1]["payload"]["evidence"]["unwarranted"] == 1


def test_cli_add_goes_through_once_the_record_meets_the_bar(tmp_path: Path) -> None:
    _seed(tmp_path, clean=59)
    done = _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "earned",
                    max_error="0.05")
    assert done.returncode == 0, done.stderr
    assert "fewer than 5.0%" in done.stdout and "WITHOUT" not in done.stdout


def test_review_shows_the_evidence_then_and_now_and_flags_a_record_that_fell_below_the_bar(tmp_path: Path) -> None:
    _seed(tmp_path, clean=59)
    assert _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "earned",
                    "--expires-in", "90d", max_error="0.05").returncode == 0
    # Afterwards the team judges two more findings unwarranted.
    log, store = AuditLog(str(tmp_path / "audit.jsonl")), OutcomeStore(str(tmp_path / "outcomes.json"))
    for fid in ("late-1", "late-2"):
        for rec in _finding(fid, action="disable_access_key"):
            asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"],
                                               payload=rec["payload"])))
        store.record(_outcome(fid, "benign", "no_action"))

    review = _promote(tmp_path, "review", "--by", "ana", max_error="0.05")
    assert "at promotion: 0 unwarranted of 59 scored, error below 5.0%" in review.stdout
    assert "today: 2 unwarranted of 61 scored" in review.stdout and "NOT MET" in review.stdout
    assert "evidence below the bar" in review.stdout


# --- evidence that takes autonomy away ---------------------------------------

from kronagent.allowlist import SUSPENDED_UNWARRANTED, AllowlistStore  # noqa: E402
from kronagent.evidence import unwarranted_autonomy  # noqa: E402
from kronagent.schemas import ActionClass  # noqa: E402

LATER = "2099-01-01T00:00:00+00:00"       # after any promotion made during a test
EARLIER = "2020-01-01T00:00:00+00:00"


def _promoted(tmp_path: Path, action: ActionClass = ActionClass.DISABLE_ACCESS_KEY, **kw) -> AllowlistStore:
    store = AllowlistStore(str(tmp_path / "allowlist.json"))
    asyncio.run(store.add(action, by="ana", reason="earned", audit=AuditLog(str(tmp_path / "audit.jsonl")), **kw))
    return store


def _offences(store: AllowlistStore, records: list[dict], outcomes: list[AnalystOutcome]) -> dict:
    return unwarranted_autonomy(calls_from_audit(records), outcomes, store.list())


def test_an_unattended_action_the_team_judged_unwarranted_is_an_offence(tmp_path: Path) -> None:
    store = _promoted(tmp_path)
    records = _finding("bad", action="disable_access_key", disposition="auto_execute", ts=LATER)
    assert _offences(store, records, [_outcome("bad", "benign", "no_action")]) == {"disable_access_key": ["bad"]}
    assert _offences(store, records, [_outcome("bad", "malicious", "no_action")]) == {"disable_access_key": ["bad"]}


def test_what_is_not_an_offence(tmp_path: Path) -> None:
    store = _promoted(tmp_path)
    unwarranted = [_outcome(f, "benign", "no_action") for f in ("approved", "old", "other", "unsure", "good")]
    unwarranted[3] = _outcome("unsure", "inconclusive", "no_action")
    unwarranted[4] = _outcome("good")
    records = (
        _finding("approved", action="disable_access_key", disposition="requires_approval", ts=LATER)   # a person's call
        + _finding("old", action="disable_access_key", disposition="auto_execute", ts=EARLIER)       # before the promotion
        + _finding("other", action="isolate_pod", provider="kubernetes", disposition="auto_execute", ts=LATER)
        + _finding("unsure", action="disable_access_key", disposition="auto_execute", ts=LATER)
        + _finding("good", action="disable_access_key", disposition="auto_execute", ts=LATER)
        + _finding("unlabeled", action="disable_access_key", disposition="auto_execute", ts=LATER))
    assert _offences(store, records, unwarranted) == {}


def test_an_offence_on_a_provider_the_promotion_does_not_cover_is_not_its_offence(tmp_path: Path) -> None:
    store = _promoted(tmp_path, ActionClass.BLOCK_IP, providers=["aws"])
    records = _finding("cf", action="block_ip", provider="cloudflare", disposition="auto_execute", ts=LATER)
    assert _offences(store, records, [_outcome("cf", "benign", "no_action")]) == {}
    records = _finding("aws", action="block_ip", provider="aws", disposition="auto_execute", ts=LATER)
    assert _offences(store, records, [_outcome("aws", "benign", "no_action")]) == {"block_ip": ["aws"]}


def test_the_suspension_latches_is_audited_and_the_gate_refuses(tmp_path: Path) -> None:
    store, audit = _promoted(tmp_path), AuditLog(str(tmp_path / "audit.jsonl"))
    assert store.is_allowed(ActionClass.DISABLE_ACCESS_KEY, provider="aws")
    (entry, reason), = asyncio.run(store.suspend_unwarranted({"disable_access_key": ["bad-1", "bad-2"]}, audit=audit))
    assert entry.suspended_trigger == SUSPENDED_UNWARRANTED and "bad-1, bad-2" in reason
    assert not store.is_allowed(ActionClass.DISABLE_ACCESS_KEY, provider="aws")
    assert asyncio.run(store.suspend_unwarranted({"disable_access_key": ["bad-1"]}, audit=audit)) == []   # idempotent
    record = [r["payload"] for r in audit.records() if r["payload"].get("decision") == "allowlist_suspended"][-1]
    assert record["trigger"] == SUSPENDED_UNWARRANTED and record["findings"] == ["bad-1", "bad-2"]
    assert AuditLog.verify(str(tmp_path / "audit.jsonl")) == (True, None)


def _outcome_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "outcome.py", *args], cwd=REPO, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OUTCOME_PATH": str(tmp_path / "outcomes.json"),
             "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_CONNECTION_PATH": str(tmp_path / "connections.json"),
             "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": ""})


def _acted_unattended(tmp_path: Path, fid: str) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for rec in _finding(fid, action="disable_access_key", disposition="auto_execute"):
        asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"], payload=rec["payload"])))


def test_recording_an_unwarranted_outcome_suspends_the_class_until_it_is_renewed(tmp_path: Path) -> None:
    assert _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "earned").returncode == 0
    _acted_unattended(tmp_path, "f-wrong")

    recorded = _outcome_cli(tmp_path, "record", "f-wrong", "--verdict", "benign", "--action", "no_action", "--by", "ben")
    assert recorded.returncode == 0, recorded.stderr
    assert "SUSPENDED: disable_access_key" in recorded.stdout and "f-wrong" in recorded.stdout
    entry = json.loads((tmp_path / "allowlist.json").read_text())["disable_access_key"]
    assert entry["suspended_trigger"] == "unwarranted_outcome"

    # Changing the outcome afterwards does not hand the autonomy back.
    _outcome_cli(tmp_path, "record", "f-wrong", "--verdict", "malicious", "--action", "contained", "--by", "ben")
    assert json.loads((tmp_path / "allowlist.json").read_text())["disable_access_key"]["suspended_at"]

    # A renewal does, and the finding that caused the suspension can't cause another.
    assert _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "reviewed f-wrong").returncode == 0
    _outcome_cli(tmp_path, "record", "f-wrong", "--verdict", "benign", "--action", "no_action", "--by", "ben")
    listed = _promote(tmp_path, "list")
    entry = json.loads((tmp_path / "allowlist.json").read_text())["disable_access_key"]
    assert entry["suspended_at"] is None, listed.stdout + listed.stderr


def test_an_outcome_on_a_finding_a_person_approved_suspends_nothing(tmp_path: Path) -> None:
    assert _promote(tmp_path, "add", "disable_access_key", "--by", "ana", "--reason", "earned").returncode == 0
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for rec in _finding("f-approved", action="disable_access_key", disposition="requires_approval"):
        asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"], payload=rec["payload"])))
    out = _outcome_cli(tmp_path, "record", "f-approved", "--verdict", "benign", "--action", "no_action", "--by", "ben")
    assert out.returncode == 0 and "SUSPENDED" not in out.stdout
