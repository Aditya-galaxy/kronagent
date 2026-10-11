"""
Releasing a containment action: a person's decision, bounded by what Kronagent
actually did, and never automatic.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import subprocess
import sys
from pathlib import Path

from kronagent.audit import AuditLog
from kronagent.containment import ContainmentExecutor
from kronagent.release import containments_from_audit
from kronagent.schemas import ActionClass, AuditRecord, ProposedAction

REPO = Path(__file__).resolve().parent.parent


def _action(cls: ActionClass = ActionClass.DISABLE_ACCESS_KEY, target: str = "AKIAEXAMPLE", **params) -> ProposedAction:
    return ProposedAction(provider="aws", action_class=cls, target=target, rationale="r",
                          parameters=params or {"user_name": "svc"})


def _ran(fid: str, action: ProposedAction, *, executed: bool = True, request_id: str | None = None,
         ts: str = "2026-10-01T00:00:00Z") -> list[dict]:
    containment = {"action_class": action.action_class.value, "target": action.target, "executed": executed,
                   "dry_run": not executed,
                   "detail": "EXECUTED — done" if executed else "DRY-RUN — would auto-execute: x"}
    if request_id:
        containment["request_id"] = request_id
    return [{"ts": ts, "finding_id": fid, "stage": "policy",
             "payload": {"action": action.model_dump(mode="json"), "decision": {"disposition": "auto_execute"}}},
            {"ts": ts, "finding_id": fid, "stage": "containment", "payload": containment}]


def _released(fid: str, action: ProposedAction, ts: str = "2026-10-02T00:00:00Z") -> dict:
    return {"ts": ts, "finding_id": fid, "stage": "release", "payload": {
        "action_class": action.action_class.value, "target": action.target, "released": True, "operator_id": "ana"}}


# --- the ledger --------------------------------------------------------------

def test_only_what_ran_is_in_place_and_it_carries_the_action_as_planned() -> None:
    a = _action()
    records = _ran("f1", a) + _ran("f2", _action(target="AKIAOTHER"), executed=False)
    (c,) = containments_from_audit(records)
    assert (c.finding_id, c.executed, c.approved_request) == ("f1", True, None)
    assert c.action == a                                  # provider, tenant and parameters come from the record
    assert len(containments_from_audit(records, include_dry_run=True)) == 2


def test_an_approved_action_is_marked_as_a_persons() -> None:
    (c,) = containments_from_audit(_ran("f1", _action(), request_id="apr-123"))
    assert c.approved_request == "apr-123"


def test_a_release_marks_the_action_released_and_a_later_containment_is_in_place_again() -> None:
    a = _action()
    records = _ran("f1", a) + [_released("f1", a)] + _ran("f1", a, ts="2026-10-03T00:00:00Z")
    first, second = containments_from_audit(records)
    assert first.released_at == "2026-10-02T00:00:00Z" and first.released_by == "ana"
    assert second.released_at is None


def test_a_failed_or_dry_run_release_releases_nothing() -> None:
    a = _action()
    attempt = _released("f1", a)
    attempt["payload"]["released"] = False
    (c,) = containments_from_audit(_ran("f1", a) + [attempt])
    assert c.released_at is None


# --- the executor ------------------------------------------------------------

class _Adapter:
    provider = "aws"

    def __init__(self, fail: bool = False) -> None:
        self.released: list[ProposedAction] = []
        self.fail = fail

    def plan(self, action):
        return ["contain()"], "undo by hand", "contain"

    def plan_release(self, action):
        if action.action_class is ActionClass.TERMINATE_INSTANCE:
            return None
        return ["undo()"], f"undo {action.target}"

    async def release(self, action):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.released.append(action)
        return f"undid {action.target}"


def _executor(settings, adapter, *, dry_run: bool) -> ContainmentExecutor:
    return ContainmentExecutor(dataclasses.replace(settings, dry_run=dry_run), {"aws": adapter})


def test_dry_run_plans_a_release_and_changes_nothing(settings) -> None:
    adapter = _Adapter()
    out = asyncio.run(_executor(settings, adapter, dry_run=True).release(_action()))
    assert (out.released, out.dry_run, out.supported) == (False, True, True)
    assert out.detail.startswith("DRY-RUN — would release") and out.api_calls == ["undo()"]
    assert adapter.released == []


def test_a_live_release_runs_the_adapter(settings) -> None:
    adapter = _Adapter()
    out = asyncio.run(_executor(settings, adapter, dry_run=False).release(_action()))
    assert out.released and out.detail == "RELEASED — undid AKIAEXAMPLE" and len(adapter.released) == 1


def test_an_action_that_cannot_be_undone_says_so_and_gives_the_manual_steps(settings) -> None:
    adapter = _Adapter()
    out = asyncio.run(_executor(settings, adapter, dry_run=False).release(
        _action(ActionClass.TERMINATE_INSTANCE, "i-1")))
    assert (out.released, out.supported) == (False, False) and "By hand: undo by hand" in out.detail
    assert adapter.released == []

    class Bare:                                       # an adapter written before release existed
        provider = "aws"

        def plan(self, action):
            return ["x"], "manual steps", "x"

    out = asyncio.run(_executor(settings, Bare(), dry_run=False).release(_action()))
    assert out.supported is False and "manual steps" in out.detail


def test_a_failed_release_is_reported_not_raised(settings) -> None:
    out = asyncio.run(_executor(settings, _Adapter(fail=True), dry_run=False).release(_action()))
    assert out.released is False and out.error == "AccessDenied" and "RELEASE FAILED" in out.detail


# --- the CLI (dry-run: the rehearsal path) -----------------------------------

def _seed(tmp_path: Path, *groups: list[dict]) -> None:
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for rec in (r for g in groups for r in g):
        asyncio.run(log.record(AuditRecord(finding_id=rec["finding_id"], stage=rec["stage"], payload=rec["payload"])))


def _cli(tmp_path: Path, *args: str, **extra: str) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
           "KRONAGENT_APPROVAL_PATH": str(tmp_path / "approvals.json"),
           "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
           "KRONAGENT_CONNECTION_PATH": str(tmp_path / "connections.json"),
           "KRONAGENT_QUARANTINE_NACL_ID": "acl-0quarantine", **extra}
    return subprocess.run([sys.executable, "approve.py", *args], cwd=REPO, capture_output=True, text=True, env=env)


def _stages(tmp_path: Path) -> list[dict]:
    return [json.loads(line)["record"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


def test_cli_rehearses_a_release_in_dry_run_and_audits_who_asked_and_why(tmp_path: Path) -> None:
    _seed(tmp_path, _ran("f1", _action(), executed=False))
    listed = _cli(tmp_path, "executed")
    assert "f1  disable_access_key  AKIAEXAMPLE" in listed.stdout and "dry-run: would be in place" in listed.stdout

    done = _cli(tmp_path, "release", "f1", "disable_access_key", "--by", "ana", "--reason", "owner confirmed it")
    assert done.returncode == 0, done.stderr
    assert "DRY-RUN — would release: re-activate access key AKIAEXAMPLE" in done.stdout
    assert "Status='Active'" in done.stdout and "nothing was changed" in done.stdout

    request, result = [r for r in _stages(tmp_path) if r["stage"].startswith("release")]
    assert request["stage"] == "release_request" and request["payload"]["reason"] == "owner confirmed it"
    assert request["payload"]["contained_by"] == "policy (unattended)"
    assert result["stage"] == "release" and result["payload"]["released"] is False
    # A rehearsal releases nothing, so the action is still listed as in place.
    assert "f1  disable_access_key" in _cli(tmp_path, "executed").stdout


def test_cli_can_only_release_what_kronagent_did(tmp_path: Path) -> None:
    _seed(tmp_path, _ran("f1", _action(), executed=False))
    for args in (("release", "f1", "block_ip"), ("release", "f-other", "disable_access_key"),
                 ("release", "f1", "disable_access_key", "--target", "AKIASOMEONEELSES")):
        out = _cli(tmp_path, *args, "--by", "ana", "--reason", "r")
        assert out.returncode == 2 and "Nothing to release" in out.stderr, args
    assert not [r for r in _stages(tmp_path) if r["stage"].startswith("release")]


def test_cli_asks_which_target_when_there_are_several(tmp_path: Path) -> None:
    _seed(tmp_path, _ran("f1", _action(ActionClass.BLOCK_IP, "198.51.100.7"), executed=False),
          _ran("f1", _action(ActionClass.BLOCK_IP, "198.51.100.8"), executed=False))
    vague = _cli(tmp_path, "release", "f1", "block_ip", "--by", "ana", "--reason", "r")
    assert vague.returncode == 2 and "198.51.100.7, 198.51.100.8" in vague.stderr
    exact = _cli(tmp_path, "release", "f1", "block_ip", "--target", "198.51.100.8", "--by", "ana", "--reason", "r")
    assert exact.returncode == 0 and "198.51.100.8/32" in exact.stdout


def test_cli_refuses_under_the_kill_switch_and_reports_an_action_it_cannot_undo(tmp_path: Path) -> None:
    _seed(tmp_path, _ran("f1", _action(), executed=False),
          _ran("f2", _action(ActionClass.ISOLATE_INSTANCE_SG, "i-0abc"), executed=False))
    halted = _cli(tmp_path, "release", "f1", "disable_access_key", "--by", "ana", "--reason", "r",
                  KRONAGENT_KILL_SWITCH="true")
    assert halted.returncode == 3 and "KILL SWITCH" in halted.stderr
    manual = _cli(tmp_path, "release", "f2", "isolate_instance_sg", "--by", "ana", "--reason", "r")
    assert manual.returncode == 5 and "can't run the release" in manual.stdout and "By hand:" in manual.stdout
