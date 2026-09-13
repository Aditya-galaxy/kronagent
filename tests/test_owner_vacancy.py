"""
Owner vacancy — an allowlist entry whose owner has left stops granting autonomy.

Ownership exists so that every standing grant of autonomy has somebody who can
be asked to renew it. People leave; entries do not. Before this, an owner who
was deactivated, demoted, or moved off a customer kept "owning" their entries
indefinitely, and the entries kept executing — the handover was silent, and the
silent handover is where drift enters.

What is pinned here:
  * the gate refuses such an entry immediately, with no sweep in the loop;
  * the sweep latches the withdrawal into the audit chain, exactly once, and
    re-adding the person to a registry file does not quietly undo it;
  * a registry that cannot be read refuses autonomy but latches nothing — a
    broken file has not made anyone leave;
  * the only ways back are a renewal or a reassignment to someone in standing,
    and no write path can hand an entry to someone who could not renew it;
  * with no registry at all, owner standing is reported as unchecked rather
    than passed.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.allowlist import (
    SUSPENDED_OWNER_VACANT, AllowlistStore, OwnerNotInStandingError,
)
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.identity import ALL_TENANTS, hash_token, owner_vacancy, owner_vacancy_checker
from kronagent.policy import PolicyEngine
from kronagent.preflight import run_preflight
from kronagent.schemas import ActionClass, ProposedAction

REPO_ROOT = Path(__file__).resolve().parent.parent


def _operator(roles=("admin",), *, active=True, tenants=None, token=None) -> dict:
    record = {"display_name": "x", "roles": list(roles), "active": active}
    if tenants is not None:
        record["tenants"] = tenants
    if token is not None:
        record["token_sha256"] = hash_token(token)
    return record


@pytest.fixture
def registry(tmp_path) -> Path:
    path = tmp_path / "operators.json"
    path.write_text(json.dumps({
        "alice": _operator(token="secret"),
        "dana": _operator(),
    }))
    return path


def _edit(registry: Path, operator_id: str, **changes) -> None:
    data = json.loads(registry.read_text())
    if changes.get("delete"):
        data.pop(operator_id)
    else:
        data[operator_id].update(changes)
    registry.write_text(json.dumps(data))


def _governance(audit: AuditLog, decision: str) -> list[dict]:
    return [r for r in audit.records()
            if r.get("stage") == "governance" and r["payload"].get("decision") == decision]


# --------------------------------------------------------------------------- #
# The standing test itself
# --------------------------------------------------------------------------- #

def test_an_active_admin_with_tenant_access_is_in_standing(registry) -> None:
    assert owner_vacancy(str(registry), "dana", "default") is None


@pytest.mark.parametrize("change, expected", [
    ({"delete": True}, "not in the operator registry"),
    ({"active": False}, "deactivated"),
    ({"roles": ["approver"]}, "promote permission"),
    ({"tenants": ["tenant-b"]}, "access to tenant 'default'"),
])
def test_each_way_an_owner_can_leave_is_a_definitive_vacancy(registry, change, expected) -> None:
    _edit(registry, "dana", **change)
    vacancy = owner_vacancy(str(registry), "dana", "default")
    assert vacancy is not None
    assert vacancy.definitive is True
    assert expected in vacancy.reason


def test_tenant_access_is_judged_per_tenant(registry) -> None:
    _edit(registry, "dana", tenants=["tenant-a"])
    assert owner_vacancy(str(registry), "dana", "tenant-a") is None
    assert owner_vacancy(str(registry), "dana", "tenant-b") is not None
    _edit(registry, "dana", tenants=[ALL_TENANTS])
    assert owner_vacancy(str(registry), "dana", "tenant-b") is None


@pytest.mark.parametrize("contents", ["{not json", "{}", "[]"])
def test_an_unreadable_registry_is_a_vacancy_but_not_a_definitive_one(registry, contents) -> None:
    registry.write_text(contents)
    vacancy = owner_vacancy(str(registry), "dana", "default")
    assert vacancy is not None
    assert vacancy.definitive is False


def test_no_registry_means_owner_standing_is_not_checked(tmp_path) -> None:
    assert owner_vacancy_checker("", "default") is None
    assert owner_vacancy_checker(str(tmp_path / "missing.json"), "default") is None


# --------------------------------------------------------------------------- #
# The gate and the sweep
# --------------------------------------------------------------------------- #

@pytest.fixture
def store(tmp_path) -> AllowlistStore:
    return AllowlistStore(str(tmp_path / "allowlist.json"))


async def test_the_gate_refuses_an_entry_whose_owner_left_before_any_sweep(
        store, audit_log, registry) -> None:
    check = owner_vacancy_checker(str(registry), "default")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="dana", reason="r", audit=audit_log,
                    owner_check=check)
    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is True

    _edit(registry, "dana", active=False)
    allowed, why = store.evaluate(ActionClass.BLOCK_IP, owner_check=check)
    assert allowed is False
    assert "deactivated" in why
    assert store.list()[0].is_suspended is False   # refused, not yet latched


async def test_the_sweep_latches_once_and_reinstating_the_owner_does_not_undo_it(
        store, audit_log, registry) -> None:
    check = owner_vacancy_checker(str(registry), "default")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="dana", reason="quiet for 30d",
                    audit=audit_log, owner_check=check)
    store.record_fired(ActionClass.BLOCK_IP)
    _edit(registry, "dana", delete=True)

    swept = await store.suspend_vacant_owners(audit=audit_log, owner_check=check)
    assert [e.action_class for e, _ in swept] == ["block_ip"]
    assert await store.suspend_vacant_owners(audit=audit_log, owner_check=check) == []

    records = _governance(audit_log, "allowlist_suspended")
    assert len(records) == 1
    payload = records[0]["payload"]
    assert payload["trigger"] == SUSPENDED_OWNER_VACANT
    assert payload["owner"] == "dana" and payload["promoted_by"] == "alice"
    assert payload["promotion_reason"] == "quiet for 30d"
    assert payload["fire_count"] == 1

    # Putting dana back in the file is not a decision about autonomy.
    registry.write_text(json.dumps({"alice": _operator(token="secret"), "dana": _operator()}))
    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is False
    assert store.active() == []
    assert store.list()[0].suspended_reason is not None


async def test_an_unreadable_registry_refuses_at_the_gate_but_latches_nothing(
        store, audit_log, registry) -> None:
    check = owner_vacancy_checker(str(registry), "default")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="dana", reason="r", audit=audit_log,
                    owner_check=check)
    original = registry.read_text()
    registry.write_text("{truncated")

    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is False
    assert await store.suspend_vacant_owners(audit=audit_log, owner_check=check) == []
    assert _governance(audit_log, "allowlist_suspended") == []

    registry.write_text(original)
    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is True


async def test_the_sweep_without_a_directory_does_nothing(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="ghost", reason="r", audit=audit_log)
    assert await store.suspend_vacant_owners(audit=audit_log, owner_check=None) == []
    assert store.is_allowed(ActionClass.BLOCK_IP) is True


# --------------------------------------------------------------------------- #
# The ways back, and the writes that must refuse
# --------------------------------------------------------------------------- #

async def _suspended(store, audit_log, registry):
    check = owner_vacancy_checker(str(registry), "default")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="dana", reason="r", audit=audit_log,
                    owner_check=check)
    _edit(registry, "dana", active=False)
    await store.suspend_vacant_owners(audit=audit_log, owner_check=check)
    return check


async def test_reassigning_to_an_owner_in_standing_lifts_the_suspension(
        store, audit_log, registry) -> None:
    check = await _suspended(store, audit_log, registry)
    entry = await store.set_owner(ActionClass.BLOCK_IP, owner="alice", by="alice",
                                  reason="dana left", audit=audit_log, owner_check=check)
    assert entry.is_suspended is False
    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is True
    payload = _governance(audit_log, "allowlist_reassign")[-1]["payload"]
    assert "deactivated" in payload["lifted_suspension"]


async def test_reassigning_to_someone_not_in_standing_writes_nothing(
        store, audit_log, registry) -> None:
    check = await _suspended(store, audit_log, registry)
    before = len(audit_log.records())
    with pytest.raises(OwnerNotInStandingError):
        await store.set_owner(ActionClass.BLOCK_IP, owner="mallory", by="alice",
                              reason="r", audit=audit_log, owner_check=check)
    assert store.list()[0].owner == "dana"
    assert store.list()[0].is_suspended is True
    assert len(audit_log.records()) == before


async def test_a_reassignment_does_not_lift_a_suspension_it_does_not_answer(
        store, audit_log, registry) -> None:
    """Handing an entry to a new owner answers "who is accountable" — not
    whatever else withdrew its authority."""
    check = owner_vacancy_checker(str(registry), "default")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="dana", reason="r", audit=audit_log)
    raw = store._read_all()
    raw["block_ip"].update(suspended_at="2026-09-01T00:00:00+00:00",
                           suspended_trigger="some_other_trigger",
                           suspended_reason="justification no longer holds")
    store._write_all(raw)

    await store.set_owner(ActionClass.BLOCK_IP, owner="alice", by="alice", reason="r",
                          audit=audit_log, owner_check=check)
    assert store.list()[0].is_suspended is True


async def test_renewing_onto_the_departed_owner_is_refused(store, audit_log, registry) -> None:
    """A renewal inherits the owner unless it names one. Inheriting someone who
    has left would re-arm an entry with nobody to ask."""
    check = await _suspended(store, audit_log, registry)
    with pytest.raises(OwnerNotInStandingError):
        await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="still needed", audit=audit_log,
                        owner_check=check)
    assert store.list()[0].is_suspended is True


async def test_renewing_with_a_new_owner_lifts_the_suspension(store, audit_log, registry) -> None:
    check = await _suspended(store, audit_log, registry)
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", owner="alice", reason="still needed",
                    audit=audit_log, owner_check=check)
    assert store.is_allowed(ActionClass.BLOCK_IP, owner_check=check) is True
    assert _governance(audit_log, "allowlist_add")[-1]["payload"]["lifted_suspension"]


def test_every_owner_setting_write_path_checks_standing() -> None:
    """Every production call that can put a name in `owner` passes `owner_check`.

    The store only refuses when it is handed a check, so a write path that
    forgets one — a new console endpoint, a ChatOps command — could make
    anyone the owner of standing autonomy. Found with `ast`, so a call split
    across lines or wrapped in a try block is still seen.
    """
    sources = [REPO_ROOT / "promote.py", *sorted((REPO_ROOT / "kronagent").glob("*.py"))]
    calls, missing = 0, []
    for path in sources:
        if path.name == "allowlist.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            keywords = {k.arg for k in node.keywords}
            is_owner_write = (node.func.attr == "set_owner"
                              or (node.func.attr == "add" and {"reason", "audit"} <= keywords))
            if not is_owner_write:
                continue
            calls += 1
            if "owner_check" not in keywords:
                missing.append(f"{path.name}:{node.lineno}")
    assert calls >= 4, f"scanner found only {calls} owner writes — it has gone blind"
    assert missing == [], f"owner writes without owner_check: {missing}"


# --------------------------------------------------------------------------- #
# The policy engine, the pipeline, preflight and the CLI
# --------------------------------------------------------------------------- #

def _settings(tmp_path, registry=None) -> Settings:
    return Settings(
        dry_run=True,
        allowlist_store_path=str(tmp_path / "allowlist.json"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        approval_store_path=str(tmp_path / "approvals.json"),
        operator_registry_path=str(registry) if registry else "",
    )


def _action(tenant_id: str = "default") -> ProposedAction:
    return ProposedAction(provider="kubernetes", tenant_id=tenant_id,
                          action_class=ActionClass.ISOLATE_POD, target="pod-1", rationale="r")


async def test_policy_routes_to_approval_and_says_the_owner_left(tmp_path, registry) -> None:
    settings = _settings(tmp_path, registry)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="alice", owner="dana", reason="r",
                    audit=AuditLog(settings.audit_log_path))
    engine = PolicyEngine(settings, store)
    assert engine.decide(_action(), severity=8.0).disposition == "auto_execute"

    _edit(registry, "dana", roles=["viewer"])
    decision = engine.decide(_action(), severity=8.0)
    assert decision.disposition == "requires_approval"
    assert "dana" in decision.reason and "promote permission" in decision.reason


async def test_policy_judges_owner_standing_in_the_actions_tenant(tmp_path, registry) -> None:
    """An owner can keep their job and still lose access to one customer."""
    settings = _settings(tmp_path, registry)
    _edit(registry, "dana", tenants=["tenant-a"])
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="alice", owner="dana", reason="r",
                    audit=AuditLog(settings.audit_log_path))
    engine = PolicyEngine(settings, store)
    assert engine.decide(_action("tenant-a"), severity=8.0).disposition == "auto_execute"
    assert engine.decide(_action("tenant-b"), severity=8.0).disposition == "requires_approval"


async def test_policy_without_a_registry_does_not_check_owners(tmp_path) -> None:
    settings = _settings(tmp_path)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="whoever", reason="r",
                    audit=AuditLog(settings.audit_log_path))
    assert PolicyEngine(settings, store).decide(_action(), severity=8.0).disposition \
        == "auto_execute"


async def test_the_pipeline_records_the_suspension_before_the_decision_it_causes(
        tmp_path, registry) -> None:
    from kronagent.containment import ContainmentExecutor
    from kronagent.orchestrator import Orchestrator

    from .conftest import FakeContainmentAdapter
    from .test_orchestrator import FakeTriageEngine, _drain, _finding, _queued, _verdict

    settings = _settings(tmp_path, registry)
    audit = AuditLog(settings.audit_log_path)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="alice", owner="dana", reason="r", audit=audit)
    _edit(registry, "dana", delete=True)

    triage = FakeTriageEngine(_verdict("f-1", actionable=True), candidates=[_action()])
    adapter = FakeContainmentAdapter(provider="kubernetes")
    orch = Orchestrator(settings, triage=triage, policy=PolicyEngine(settings, store),
                        containment=ContainmentExecutor(settings, {"kubernetes": adapter}),
                        audit=audit)
    await _drain(orch, [_queued(_finding(finding_id="f-1"))[0]])

    records = audit.records()
    stages = [(r["stage"], r["payload"].get("decision")) for r in records]
    suspended_at = stages.index(("governance", "allowlist_suspended"))
    policy_at = next(i for i, r in enumerate(records) if r["stage"] == "policy")
    assert suspended_at < policy_at
    assert records[policy_at]["payload"]["decision"]["disposition"] == "requires_approval"
    assert store.list()[0].fire_count == 0


async def test_preflight_fails_on_an_owner_not_in_standing(tmp_path, registry) -> None:
    settings = _settings(tmp_path, registry)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.ISOLATE_POD, by="alice", owner="dana", reason="r",
                    audit=AuditLog(settings.audit_log_path), expires_in=None)
    _edit(registry, "dana", active=False)
    checks = {c.name: c for c in run_preflight(settings).checks}
    assert checks["allowlist:owners"].status == "fail"
    assert "isolate_pod" in checks["allowlist:owners"].detail
    # Not counted in the headline "can run unattended" number either.
    assert "isolate_pod" not in getattr(checks.get("autonomy"), "detail", "")


async def test_preflight_says_owner_standing_is_unchecked_without_a_registry(tmp_path) -> None:
    settings = _settings(tmp_path)
    await AllowlistStore(settings.allowlist_store_path).add(
        ActionClass.ISOLATE_POD, by="whoever", reason="r", audit=AuditLog(settings.audit_log_path))
    checks = {c.name: c for c in run_preflight(settings).checks}
    assert checks["allowlist:owners"].status == "warn"
    assert "not checked" in checks["allowlist:owners"].detail


def _cli(args: list[str], tmp_path, registry) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), *args],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ,
             "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OPERATOR_REGISTRY": str(registry)},
    )


def test_cli_refuses_an_owner_not_in_standing_and_suspends_on_departure(tmp_path, registry) -> None:
    auth = ["--as", "alice", "--token", "secret"]
    refused = _cli(["add", "block_ip", "--provider", "aws", *auth, "--reason", "r", "--owner", "mallory"],
                   tmp_path, registry)
    assert refused.returncode == 2
    assert "mallory" in refused.stderr

    assert _cli(["add", "block_ip", "--provider", "aws", *auth, "--reason", "r", "--owner", "dana"],
                tmp_path, registry).returncode == 0
    _edit(registry, "dana", active=False)

    listed = _cli(["list"], tmp_path, registry)
    assert "SUSPENDED: block_ip" in listed.stderr
    assert "SUSPENDED — owner 'dana' is deactivated" in listed.stdout

    review = _cli(["review", *auth], tmp_path, registry)
    assert "suspended" in review.stdout

    back = _cli(["reassign", "block_ip", *auth, "--to", "alice", "--reason", "dana left"],
                tmp_path, registry)
    assert back.returncode == 0, back.stderr
    assert "SUSPENDED" not in _cli(["list"], tmp_path, registry).stdout
