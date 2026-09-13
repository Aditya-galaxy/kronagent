"""
AllowlistStore — the earn-trust dial. Every write must be audited, and reads
must reflect the store's live state (no restart needed).

The expiry tests carry the same weight as the policy engine's: an entry whose
TTL has lapsed must stop granting autonomy *at the gate*, not merely when some
sweep gets around to running. Time is injected, never slept on, so a test can
assert what the store does 91 days from now.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kronagent.allowlist import (
    DEFAULT_STALE_AFTER_DAYS, AllowlistEntry, AllowlistStore, DurationError, parse_duration,
)
from kronagent.audit import AuditLog
from kronagent.identity import hash_token
from kronagent.schemas import ActionClass

REPO_ROOT = Path(__file__).resolve().parent.parent


def _in(**kwargs) -> datetime:
    """A point in time relative to now, for injecting into the store."""
    return datetime.now(timezone.utc) + timedelta(**kwargs)


@pytest.fixture
def store(tmp_path) -> AllowlistStore:
    return AllowlistStore(str(tmp_path / "allowlist.json"))


def _governance(audit_log: AuditLog) -> list[dict]:
    records = [json.loads(l)["record"] for l in open(audit_log._path) if l.strip()]
    return [r for r in records if r["stage"] == "governance"]


def test_fresh_store_is_empty(store: AllowlistStore) -> None:
    assert store.list() == []
    assert store.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is False


async def test_add_makes_action_allowed(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.DISABLE_ACCESS_KEY, by="alice", reason="proven safe", audit=audit_log)
    assert store.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True
    entries = store.list()
    assert len(entries) == 1
    assert entries[0].promoted_by == "alice"
    assert entries[0].reason == "proven safe"


async def test_add_writes_governance_audit_record(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.ISOLATE_POD, by="bob", reason="k8s netpol validated", audit=audit_log)
    lines = audit_log._path
    records = [json.loads(l)["record"] for l in open(lines) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert len(gov) == 1
    assert gov[0]["payload"]["decision"] == "allowlist_add"
    assert gov[0]["payload"]["action_class"] == "isolate_pod"
    assert gov[0]["payload"]["by"] == "bob"
    assert gov[0]["payload"]["reason"] == "k8s netpol validated"
    assert gov[0]["payload"]["already_present"] is False


async def test_duplicate_add_flags_already_present(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r1", audit=audit_log)
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r2 (re-confirm)", audit=audit_log)
    records = [json.loads(l)["record"] for l in open(audit_log._path) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert gov[0]["payload"]["already_present"] is False
    assert gov[1]["payload"]["already_present"] is True
    # Second add wins on content (last-write, not append-only for the live entry).
    assert store.list()[0].reason == "r2 (re-confirm)"


async def test_remove_revokes_autonomy(store: AllowlistStore, audit_log: AuditLog) -> None:
    await store.add(ActionClass.CORDON_NODE, by="a", reason="r", audit=audit_log)
    assert store.is_allowed(ActionClass.CORDON_NODE) is True
    existed = await store.remove(ActionClass.CORDON_NODE, by="a", reason="demoting", audit=audit_log)
    assert existed is True
    assert store.is_allowed(ActionClass.CORDON_NODE) is False


async def test_remove_nonexistent_is_noop_but_still_audited(store: AllowlistStore, audit_log: AuditLog) -> None:
    existed = await store.remove(ActionClass.BLOCK_IP, by="a", reason="testing no-op", audit=audit_log)
    assert existed is False
    records = [json.loads(l)["record"] for l in open(audit_log._path) if l.strip()]
    gov = [r for r in records if r["stage"] == "governance"]
    assert len(gov) == 1
    assert gov[0]["payload"]["decision"] == "allowlist_remove"
    assert gov[0]["payload"]["existed"] is False


def test_seed_applies_only_on_first_creation(tmp_path) -> None:
    path = str(tmp_path / "allowlist.json")
    seeded = AllowlistStore(path, seed=frozenset({"disable_access_key"}))
    assert seeded.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True

    # A second store pointed at the same (now-existing) file must NOT be
    # reseeded, even with a different seed -- that would silently clobber
    # live governance state on every restart.
    reopened = AllowlistStore(path, seed=frozenset({"block_ip"}))
    assert reopened.is_allowed(ActionClass.DISABLE_ACCESS_KEY) is True
    assert reopened.is_allowed(ActionClass.BLOCK_IP) is False


def test_no_seed_leaves_store_unwritten(tmp_path) -> None:
    path = str(tmp_path / "allowlist.json")
    AllowlistStore(path, seed=frozenset())
    assert not os.path.exists(path)


# --------------------------------------------------------------------------- #
# Duration parsing — a governance TTL, so a misread is a safety bug
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("90d", timedelta(days=90)),
    ("2w", timedelta(weeks=2)),
    ("12h", timedelta(hours=12)),
    ("30m", timedelta(minutes=30)),
    ("45s", timedelta(seconds=45)),
    (" 7D ", timedelta(days=7)),
])
def test_parse_duration_accepts_suffixed_units(raw: str, expected: timedelta) -> None:
    assert parse_duration(raw) == expected


@pytest.mark.parametrize("raw", ["90", "", "d", "-1d", "0d", "1.5d", "90 days", None])
def test_parse_duration_rejects_ambiguous_input(raw) -> None:
    """A bare '90' could mean days, hours, or seconds. Guessing wrong on a
    governance TTL means autonomy lapses (or persists) for the wrong length of
    time, so the unit is mandatory rather than defaulted."""
    with pytest.raises(DurationError):
        parse_duration(raw)


# --------------------------------------------------------------------------- #
# Expiry — autonomy that has to be re-earned
# --------------------------------------------------------------------------- #

async def test_entry_without_ttl_is_standing_authority(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log)
    assert store.list()[0].expires_at is None
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=3650)) is True


async def test_expired_entry_is_denied_at_the_gate_before_any_sweep(store, audit_log) -> None:
    """The load-bearing property: expiry is enforced by the read path the
    policy engine uses, so the lapse is immediate. If it depended on a sweep
    having run, a stalled cron would silently extend autonomy."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=90))
    assert store.is_allowed(ActionClass.BLOCK_IP) is True
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=89)) is True
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=91)) is False
    # ...and no sweep has run: the entry is still on file.
    assert [e.action_class for e in store.list()] == ["block_ip"]


async def test_add_records_the_ttl_in_the_audit_chain(store, audit_log) -> None:
    entry = await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log,
                            expires_in=timedelta(days=90))
    payload = _governance(audit_log)[0]["payload"]
    assert payload["decision"] == "allowlist_add"
    assert payload["expires_at"] == entry.expires_at


async def test_expiry_is_audited_as_a_governance_event(store, audit_log) -> None:
    """A lapse is a demotion nobody typed. It gets its own hash-chained record,
    carrying the promotion it reverses — six months on, that record is what
    says the authority ended and what it was for."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="30 days incident-free",
                    audit=audit_log, expires_in=timedelta(days=90))
    store.record_fired(ActionClass.BLOCK_IP)

    lapsed = await store.expire_due(audit=audit_log, now=_in(days=91))
    assert [e.action_class for e in lapsed] == ["block_ip"]

    payload = _governance(audit_log)[-1]["payload"]
    assert payload["decision"] == "allowlist_expired"
    assert payload["action_class"] == "block_ip"
    assert payload["by"] == "system"
    assert payload["promoted_by"] == "alice"
    assert payload["promotion_reason"] == "30 days incident-free"
    assert payload["fire_count"] == 1
    assert payload["identity_verified"] is False


async def test_expiry_sweep_clears_the_entry_and_is_idempotent(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))
    await store.expire_due(audit=audit_log, now=_in(days=2))
    assert store.list() == []

    # One lapse, one record — no matter how many callers sweep.
    assert await store.expire_due(audit=audit_log, now=_in(days=3)) == []
    assert len([g for g in _governance(audit_log)
                if g["payload"]["decision"] == "allowlist_expired"]) == 1


async def test_expiry_sweep_leaves_live_entries_alone(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))
    await store.add(ActionClass.ISOLATE_POD, by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=90))
    await store.add(ActionClass.CORDON_NODE, by="a", reason="r", audit=audit_log)

    await store.expire_due(audit=audit_log, now=_in(days=2))
    assert [e.action_class for e in store.list()] == ["cordon_node", "isolate_pod"]


async def test_renewal_resets_the_clock_and_keeps_the_firing_history(store, audit_log) -> None:
    """Re-running `add` is the re-earn-it path: fresh reason, fresh TTL. The
    usage evidence has to survive it, or renewing an entry would erase the only
    record of whether it was ever worth having."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="initial", audit=audit_log,
                    expires_in=timedelta(days=90))
    store.record_fired(ActionClass.BLOCK_IP)
    store.record_fired(ActionClass.BLOCK_IP)

    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="bob", reason="still applies", audit=audit_log,
                    expires_in=timedelta(days=90), now=_in(days=89))
    entry = store.list()[0]
    assert entry.promoted_by == "bob"
    assert entry.reason == "still applies"
    assert entry.fire_count == 2
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=91)) is True
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=180)) is False


def test_unparseable_expiry_fails_closed(store) -> None:
    """A hand-edited or corrupt `expires_at` must not read as 'never expires' —
    that would turn a typo into permanent autonomy."""
    store._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "a", "added_at": "2026-01-01T00:00:00+00:00",
        "reason": "r", "expires_at": "next tuesday",
    }})
    assert store.is_allowed(ActionClass.BLOCK_IP) is False
    assert store.list()[0].is_expired() is True


def test_unreadable_entry_grants_nothing(store) -> None:
    store._write_all({"block_ip": {"action_class": "block_ip"}})  # missing required fields
    assert store.is_allowed(ActionClass.BLOCK_IP) is False
    assert store.list() == []


async def test_active_excludes_expired_but_list_keeps_it(store, audit_log) -> None:
    """`active()` is the set granting autonomy; `list()` is what a review reads.
    A lapsed entry has to stay visible somewhere, or nobody can decide whether
    to renew it."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))
    now = _in(days=2)
    assert [e.action_class for e in store.active(now=now)] == []
    assert [e.action_class for e in store.expired(now=now)] == ["block_ip"]
    assert [e.action_class for e in store.list()] == ["block_ip"]


# --------------------------------------------------------------------------- #
# Advance warning — a courtesy layered on a fail-closed control, built so that
# failing to deliver it can never extend anyone's authority
# --------------------------------------------------------------------------- #

async def test_expiring_within_finds_only_live_entries_with_a_deadline(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=9))
    await store.add(ActionClass.ISOLATE_POD, by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=90))       # too far out
    await store.add(ActionClass.CORDON_NODE, by="a", reason="r", audit=audit_log)  # no TTL
    await store.add(ActionClass.DISABLE_ACCESS_KEY, by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))

    due = store.expiring_within(timedelta(days=14))
    # Soonest first: the one about to lapse is the one to act on.
    assert [e.action_class for e in due] == ["disable_access_key", "block_ip"]


async def test_already_lapsed_entry_is_not_warned_about(store, audit_log) -> None:
    """There is nothing left to warn about — the authority is already gone."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))
    assert store.expiring_within(timedelta(days=14), now=_in(days=2)) == []


async def test_warn_expiring_notifies_the_owner_and_audits_it(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="30 days incident-free",
                    audit=audit_log, owner="dana", expires_in=timedelta(days=9))
    store.record_fired(ActionClass.BLOCK_IP)

    seen = []
    warned = await store.warn_expiring(audit=audit_log, within=timedelta(days=14),
                                       notify=lambda e: seen.append(e.action_class) or True)

    assert [e.action_class for e, _ in warned] == ["block_ip"]
    assert warned[0][1] is True          # delivered
    assert seen == ["block_ip"]

    payload = _governance(audit_log)[-1]["payload"]
    assert payload["decision"] == "allowlist_expiry_warning"
    assert payload["owner"] == "dana"
    assert payload["promoted_by"] == "alice"
    assert payload["promotion_reason"] == "30 days incident-free"
    assert payload["fire_count"] == 1
    assert payload["notified"] is True
    assert 0 < payload["seconds_remaining"] <= 9 * 86400


async def test_each_owner_is_warned_once_per_deadline(store, audit_log) -> None:
    """Built for a daily cron: the first run warns, the rest stay quiet."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=9))

    first = await store.warn_expiring(audit=audit_log, within=timedelta(days=14))
    second = await store.warn_expiring(audit=audit_log, within=timedelta(days=14))
    third = await store.warn_expiring(audit=audit_log, within=timedelta(days=14))

    assert len(first) == 1
    assert second == [] and third == []
    assert len([g for g in _governance(audit_log)
                if g["payload"]["decision"] == "allowlist_expiry_warning"]) == 1


async def test_renewal_arms_a_fresh_warning_for_the_new_deadline(store, audit_log) -> None:
    """Warnings are keyed on the deadline, not the class — otherwise renewing an
    entry would buy permanent silence on every future expiry."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=9))
    await store.warn_expiring(audit=audit_log, within=timedelta(days=14))

    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="renewed", audit=audit_log,
                    expires_in=timedelta(days=10))
    again = await store.warn_expiring(audit=audit_log, within=timedelta(days=14))
    assert [e.action_class for e, _ in again] == ["block_ip"]


async def test_warning_is_recorded_even_with_no_transport_configured(store, audit_log) -> None:
    """The record is the delivery state, so 'nobody was told' is itself on the
    record — and the entry still lapses on schedule either way."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=9))
    warned = await store.warn_expiring(audit=audit_log, within=timedelta(days=14), notify=None)

    assert warned[0][1] is False
    payload = _governance(audit_log)[-1]["payload"]
    assert payload["notified"] is False
    assert "NOT reachable" in payload["reason"]


async def test_a_broken_transport_does_not_stop_the_other_warnings(store, audit_log) -> None:
    """A webhook that throws is a missed courtesy, not a missed control, and it
    must not take the rest of the run down with it."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=1))
    await store.add(ActionClass.ISOLATE_POD, by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=2))

    def explode(entry):
        if entry.action_class == "block_ip":
            raise RuntimeError("webhook down")
        return True

    warned = await store.warn_expiring(audit=audit_log, within=timedelta(days=14), notify=explode)
    assert [(e.action_class, ok) for e, ok in warned] == [("block_ip", False), ("isolate_pod", True)]


async def test_warning_does_not_extend_the_entry(store, audit_log) -> None:
    """The whole safety argument: warning is not renewal."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log,
                    expires_in=timedelta(days=9))
    await store.warn_expiring(audit=audit_log, within=timedelta(days=14))
    assert store.is_allowed(ActionClass.BLOCK_IP, now=_in(days=10)) is False


# --------------------------------------------------------------------------- #
# Ownership — who is accountable now, as distinct from who decided once
# --------------------------------------------------------------------------- #

async def test_owner_defaults_to_the_promoter(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log)
    entry = store.list()[0]
    assert entry.owner == "alice"
    assert entry.promoted_by == "alice"


async def test_an_entry_can_be_promoted_on_someone_elses_behalf(store, audit_log) -> None:
    """An admin runs the command; the team lead is on the hook for renewing it."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log, owner="dana")
    entry = store.list()[0]
    assert entry.owner == "dana"
    assert entry.promoted_by == "alice"
    assert _governance(audit_log)[0]["payload"]["owner"] == "dana"


async def test_reassign_moves_the_owner_and_leaves_history_alone(store, audit_log) -> None:
    """People change teams; the decision they made in March does not."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="30 days incident-free",
                    audit=audit_log, owner="dana")
    entry = await store.set_owner(ActionClass.BLOCK_IP, owner="erin", by="alice",
                                  reason="dana moved to platform", audit=audit_log)

    assert entry.owner == "erin"
    assert entry.promoted_by == "alice"
    assert entry.reason == "30 days incident-free"
    stored = store.list()[0]
    assert (stored.owner, stored.promoted_by) == ("erin", "alice")


async def test_reassign_is_audited_with_both_owners(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log, owner="dana")
    await store.set_owner(ActionClass.BLOCK_IP, owner="erin", by="alice",
                          reason="dana moved to platform", audit=audit_log)

    payload = _governance(audit_log)[-1]["payload"]
    assert payload["decision"] == "allowlist_reassign"
    assert payload["previous_owner"] == "dana"
    assert payload["owner"] == "erin"
    assert payload["by"] == "alice"
    assert payload["reason"] == "dana moved to platform"


async def test_reassigning_an_unpromoted_class_is_a_noop_but_still_audited(store, audit_log) -> None:
    entry = await store.set_owner(ActionClass.BLOCK_IP, owner="erin", by="alice",
                                  reason="r", audit=audit_log)
    assert entry is None
    assert store.list() == []
    assert _governance(audit_log)[-1]["payload"]["existed"] is False


async def test_renewal_keeps_the_current_owner_unless_told_otherwise(store, audit_log) -> None:
    """Renewing on someone's behalf shouldn't quietly move accountability to
    whoever ran the command."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r", audit=audit_log, owner="dana")
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="still applies", audit=audit_log)
    assert store.list()[0].owner == "dana"

    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="handing over",
                    audit=audit_log, owner="erin")
    assert store.list()[0].owner == "erin"


def test_a_store_written_before_ownership_existed_still_reads(store) -> None:
    """Old entries have added_by/added_at and no owner. They load, and the
    promoter becomes the owner — an entry with nobody accountable is exactly
    the orphan this field exists to prevent."""
    store._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    entry = store.list()[0]
    assert entry.promoted_by == "alice"
    assert entry.promoted_at == "2026-01-01T00:00:00+00:00"
    assert entry.owner == "alice"
    assert store.is_allowed(ActionClass.BLOCK_IP) is True


# --------------------------------------------------------------------------- #
# Last-fired tracking — an entry that never fires is standing authority
# with no benefit
# --------------------------------------------------------------------------- #

async def test_record_fired_tracks_timestamp_and_count(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log)
    assert store.list()[0].last_fired_at is None
    assert store.list()[0].fire_count == 0

    store.record_fired(ActionClass.BLOCK_IP)
    store.record_fired(ActionClass.BLOCK_IP)
    entry = store.list()[0]
    assert entry.fire_count == 2
    assert entry.last_fired_at is not None


def test_record_fired_for_an_unpromoted_class_is_a_noop(store) -> None:
    store.record_fired(ActionClass.BLOCK_IP)
    assert store.list() == []


async def test_record_fired_is_not_audited(store, audit_log) -> None:
    """Firings are already in the audit chain as containment records. Mirroring
    them into the governance stage would bury the promote/demote/expire
    decisions that stage exists to make findable."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log)
    store.record_fired(ActionClass.BLOCK_IP)
    assert [g["payload"]["decision"] for g in _governance(audit_log)] == ["allowlist_add"]


# --------------------------------------------------------------------------- #
# Staleness — flagged for a human, never enforced
# --------------------------------------------------------------------------- #

def _entry(**kwargs) -> AllowlistEntry:
    base = {"action_class": "block_ip", "added_by": "a", "reason": "r",
            "added_at": _in(days=-200).isoformat()}
    return AllowlistEntry(**{**base, **kwargs})


def test_entry_that_never_fired_is_stale_once_it_is_old_enough() -> None:
    assert _entry().is_stale() is True


def test_fresh_promotion_that_has_not_fired_yet_is_not_stale() -> None:
    """A promotion made yesterday hasn't had a chance to fire — flagging it
    would train operators to ignore the flag."""
    assert _entry(added_at=_in(days=-1).isoformat()).is_stale() is False


def test_recently_fired_entry_is_not_stale() -> None:
    assert _entry(last_fired_at=_in(days=-1).isoformat(), fire_count=5).is_stale() is False


def test_long_unused_entry_is_stale_even_though_it_once_fired() -> None:
    entry = _entry(last_fired_at=_in(days=-90).isoformat(), fire_count=5)
    assert entry.is_stale() is True
    assert entry.is_stale(after_days=180) is False


async def test_staleness_does_not_revoke_autonomy(store, audit_log) -> None:
    """Unused is a prompt to ask a human, not grounds for the system to decide.
    Only an explicit TTL or an operator demotes anything."""
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="a", reason="r", audit=audit_log)
    later = _in(days=DEFAULT_STALE_AFTER_DAYS * 10)
    assert store.list()[0].is_stale(now=later) is True
    assert store.is_allowed(ActionClass.BLOCK_IP, now=later) is True


# --------------------------------------------------------------------------- #
# The CLI, driven as a real subprocess
# --------------------------------------------------------------------------- #

def _run(args: list[str], tmp_path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
        "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "KRONAGENT_OPERATOR_REGISTRY": "",
        "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": "",
    }
    env.pop("KRONAGENT_OPERATOR_TOKEN", None)
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), *args],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
    )


def _cli_governance(tmp_path) -> list[dict]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    records = [json.loads(l)["record"] for l in path.read_text().splitlines() if l.strip()]
    return [r for r in records if r["stage"] == "governance"]


def _write_entry(tmp_path, **fields) -> None:
    path = tmp_path / "allowlist.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    entry = {"action_class": "block_ip", "added_by": "alice", "reason": "r",
             "added_at": _in(days=-200).isoformat(), **fields}
    data[entry["action_class"]] = entry
    path.write_text(json.dumps(data))


def test_cli_add_with_ttl_reports_the_expiry(tmp_path) -> None:
    result = _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "proven safe",
                   "--expires-in", "90d"], tmp_path)
    assert result.returncode == 0
    assert "Promoted block_ip" in result.stdout
    assert "Expires" in result.stdout and "(90d)" in result.stdout
    assert _cli_governance(tmp_path)[0]["payload"]["expires_at"] is not None


def test_cli_add_without_ttl_names_it_standing_authority(tmp_path) -> None:
    """The default is still no expiry — but an operator should leave knowing
    they just granted authority that nothing will ever ask them about again."""
    result = _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    assert result.returncode == 0
    assert "standing authority" in result.stdout
    assert "--expires-in" in result.stdout


def test_cli_rejects_an_unparseable_ttl(tmp_path) -> None:
    result = _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r",
                   "--expires-in", "90"], tmp_path)
    assert result.returncode == 2
    assert "--expires-in" in result.stderr
    assert not (tmp_path / "allowlist.json").exists()  # nothing promoted


def test_cli_re_add_is_reported_as_a_renewal(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "initial", "--expires-in", "90d"], tmp_path)
    result = _run(["add", "block_ip", "--provider", "aws", "--by", "bob", "--reason", "still applies",
                   "--expires-in", "90d"], tmp_path)
    assert "Renewed block_ip" in result.stdout


def test_cli_sweeps_lapsed_entries_and_audits_the_lapse(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    _write_entry(tmp_path, expires_at=_in(days=-1).isoformat(), reason="lapsed one")

    result = _run(["list"], tmp_path)
    assert result.returncode == 0
    assert "EXPIRED: block_ip" in result.stderr
    assert "Allowlist is EMPTY" in result.stdout

    expired = [g for g in _cli_governance(tmp_path)
               if g["payload"]["decision"] == "allowlist_expired"]
    assert len(expired) == 1
    assert expired[0]["payload"]["promotion_reason"] == "lapsed one"


def test_cli_list_shows_expiry_and_firing_history(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--expires-in", "90d"], tmp_path)
    result = _run(["list"], tmp_path)
    assert "expires:" in result.stdout
    assert "last fired: NEVER" in result.stdout


def test_cli_review_surfaces_the_promotion_context(tmp_path) -> None:
    """The question this whole feature exists to answer: six months in, what was
    this entry for, who staked their name on it, and has it ever done anything?"""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "30 days incident-free"], tmp_path)
    _write_entry(tmp_path, reason="30 days incident-free")  # ...promoted 200 days ago
    result = _run(["review", "--by", "carol"], tmp_path)

    assert result.returncode == 0
    assert "30 days incident-free" in result.stdout
    assert "promoted by  alice" in result.stdout
    assert "NEVER" in result.stdout                       # never fired
    assert "no TTL" in result.stdout                      # standing authority
    assert "promote.py remove block_ip" in result.stdout  # the revoke path, in hand
    assert "1 of 1 entry needs a decision" in result.stdout


def test_cli_review_does_not_flag_a_promotion_made_yesterday(tmp_path) -> None:
    """It hasn't had a chance to fire yet. Flagging it would train operators to
    scroll past the flag that matters."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--expires-in", "90d"], tmp_path)
    result = _run(["review", "--by", "carol", "--strict"], tmp_path)
    assert result.returncode == 0
    assert "never fired" not in result.stdout
    assert "0 of 1 entry needs a decision" in result.stdout


def test_cli_review_records_that_someone_looked(tmp_path) -> None:
    """'Who reviews the allowlist six months in' is only answerable if reviewing
    is itself an audited event."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    _write_entry(tmp_path)  # ...and it has sat unused ever since
    _run(["review", "--by", "carol"], tmp_path)

    review = [g for g in _cli_governance(tmp_path)
              if g["payload"]["decision"] == "allowlist_review"][0]
    assert review["payload"]["by"] == "carol"
    assert review["payload"]["entries"] == 1
    assert review["payload"]["flagged"] == ["block_ip"]
    assert "never fired" in review["payload"]["flag_reasons"]["block_ip"]
    assert review["payload"]["identity_verified"] is False


def test_cli_review_surfaces_entries_that_lapsed_since_the_last_review(tmp_path) -> None:
    """A lapse removes the entry, so without this its only trace is one line on
    stderr of whichever command happened to trigger the sweep — which nobody was
    watching. The renew-or-let-it-go decision belongs at the next review."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "30 days incident-free"], tmp_path)
    _write_entry(tmp_path, expires_at=_in(days=-1).isoformat(), reason="30 days incident-free")
    _run(["list"], tmp_path)  # triggers the sweep

    result = _run(["review", "--by", "carol"], tmp_path)
    assert "Lapsed since the last review (1)" in result.stdout
    assert "promoted by alice" in result.stdout
    assert "30 days incident-free" in result.stdout
    assert "never fired" in result.stdout
    assert "promote.py add block_ip" in result.stdout

    # Reported once: the next review starts from this one.
    assert "Lapsed since the last review" not in _run(["review", "--by", "carol"], tmp_path).stdout


def test_cli_review_strict_fails_when_an_entry_needs_a_decision(tmp_path) -> None:
    """So a scheduled review fails loudly instead of printing into a log nobody
    reads — the exact failure mode this feature is about."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    assert _run(["review", "--by", "carol", "--strict"], tmp_path).returncode == 3


def test_cli_add_names_the_owner(tmp_path) -> None:
    result = _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--owner", "dana"], tmp_path)
    assert result.returncode == 0
    assert "Owner: dana" in result.stdout
    assert "owned by dana" in _run(["list"], tmp_path).stdout


def test_cli_reassign_moves_ownership_without_rewriting_history(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "30 days incident-free",
          "--owner", "dana"], tmp_path)
    result = _run(["reassign", "block_ip", "--to", "erin", "--by", "alice",
                   "--reason", "dana moved to platform"], tmp_path)

    assert result.returncode == 0
    assert "now owned by erin" in result.stdout
    assert "promoted by alice" in result.stdout

    review = _run(["review", "--by", "carol"], tmp_path)
    assert "owner        erin" in review.stdout
    assert "promoted by  alice" in review.stdout
    assert "30 days incident-free" in review.stdout


def test_cli_review_does_not_claim_a_reassignment_that_never_happened(tmp_path) -> None:
    """Promoting on someone else's behalf leaves owner != promoted_by from the
    start. Reporting that as "reassigned since promotion" was false on every
    such entry — and the store has no way to know, since a reassignment is an
    audit event, not a property of the entry."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--owner", "dana"], tmp_path)
    review = _run(["review", "--by", "carol"], tmp_path)
    assert "owner        dana" in review.stdout
    assert "reassigned" not in review.stdout


def test_cli_reassign_requires_promote_permission(tmp_path) -> None:
    """A viewer can read the allowlist but cannot change who is allowed to
    renew an entry — that is a governance change."""
    registry = tmp_path / "operators.json"
    registry.write_text(json.dumps({"vic": {
        "display_name": "Vic", "roles": ["viewer"],
        "token_sha256": hash_token("secret"), "active": True,
    }}))
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), "reassign", "block_ip",
         "--to", "erin", "--as", "vic", "--token", "secret", "--reason", "r"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ,
             "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OPERATOR_REGISTRY": str(registry)},
    )
    assert result.returncode == 4
    assert "promote" in result.stderr


def test_cli_review_names_the_owner_to_chase_for_a_lapsed_entry(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--owner", "dana"], tmp_path)
    _write_entry(tmp_path, owner="dana", expires_at=_in(days=-1).isoformat())
    _run(["list"], tmp_path)  # triggers the sweep

    result = _run(["review", "--by", "carol"], tmp_path)
    assert "owned by dana — the renew-or-drop call is theirs" in result.stdout


def test_cli_warn_expiring_reports_and_records_once(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "30 days incident-free",
          "--owner", "dana"], tmp_path)
    _write_entry(tmp_path, owner="dana", reason="30 days incident-free",
                 expires_at=_in(days=9).isoformat())

    first = _run(["warn-expiring", "--within", "14d"], tmp_path)
    assert first.returncode == 0
    assert "Warned about 1 expiring entry" in first.stdout
    assert "owner dana — NOT DELIVERED — no chat transport configured" in first.stdout
    assert "promote.py add block_ip" in first.stdout
    assert "Doing nothing is a valid answer" in first.stdout

    second = _run(["warn-expiring", "--within", "14d"], tmp_path)
    assert "No allowlist entries expiring within 14d" in second.stdout
    assert len([g for g in _cli_governance(tmp_path)
                if g["payload"]["decision"] == "allowlist_expiry_warning"]) == 1


def test_cli_warn_expiring_dry_run_records_nothing(tmp_path) -> None:
    """So an operator can see who is about to be pinged without consuming the
    one warning that entry gets."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--owner", "dana"], tmp_path)
    _write_entry(tmp_path, owner="dana", expires_at=_in(days=9).isoformat())

    dry = _run(["warn-expiring", "--dry-run"], tmp_path)
    assert "DRY RUN — 1 entry would be warned about" in dry.stdout
    assert _cli_governance(tmp_path) and not [
        g for g in _cli_governance(tmp_path)
        if g["payload"]["decision"] == "allowlist_expiry_warning"
    ]

    # ...and the real run still warns.
    assert "Warned about 1" in _run(["warn-expiring"], tmp_path).stdout


def test_cli_warn_expiring_ignores_entries_that_are_not_close(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--expires-in", "90d"], tmp_path)
    result = _run(["warn-expiring", "--within", "14d"], tmp_path)
    assert "No allowlist entries expiring within 14d" in result.stdout


def test_cli_warn_expiring_needs_no_operator_identity(tmp_path) -> None:
    """It's a system action for cron — nobody is deciding anything, the TTL
    already did. Requiring --by would just invite a shared fake identity."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    _write_entry(tmp_path, expires_at=_in(days=3).isoformat())
    result = _run(["warn-expiring"], tmp_path)
    assert result.returncode == 0
    assert _cli_governance(tmp_path)[-1]["payload"]["by"] == "system"


def test_cli_reports_an_entry_whose_action_class_no_longer_exists(tmp_path) -> None:
    """A renamed or removed action leaves an orphan entry. It grants nothing —
    the policy engine can never propose that class — but the review has to
    survive finding one and tell the operator to clean it up."""
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r"], tmp_path)
    _write_entry(tmp_path, action_class="retired_action")

    listed = _run(["list"], tmp_path)
    assert listed.returncode == 0
    assert "UNKNOWN action class" in listed.stdout

    review = _run(["review", "--by", "carol"], tmp_path)
    assert review.returncode == 0
    assert "unknown action class" in review.stdout


def test_cli_review_strict_passes_on_an_empty_allowlist(tmp_path) -> None:
    result = _run(["review", "--by", "carol", "--strict"], tmp_path)
    assert result.returncode == 0
    assert "Nothing to review" in result.stdout


def test_cli_review_flags_an_entry_expiring_soon(tmp_path) -> None:
    _run(["add", "block_ip", "--provider", "aws", "--by", "alice", "--reason", "r", "--expires-in", "10d"], tmp_path)
    within = _run(["review", "--by", "carol", "--expiring-within", "14d"], tmp_path)
    assert "expiring soon" in within.stdout

    outside = _run(["review", "--by", "carol", "--expiring-within", "2d"], tmp_path)
    assert "expiring soon" not in outside.stdout


def test_cli_review_requires_an_attributable_reviewer(tmp_path) -> None:
    """An anonymous review records nothing worth having."""
    result = _run(["review"], tmp_path)
    assert result.returncode == 4
    assert "--by" in result.stderr


def test_cli_review_is_allowed_for_a_viewer_role(tmp_path) -> None:
    """Reviewing is a read: a viewer can run it. Renewing what it flags still
    needs PROMOTE — separation of duty survives the new command."""
    registry = tmp_path / "operators.json"
    registry.write_text(json.dumps({"vic": {
        "display_name": "Vic", "roles": ["viewer"],
        "token_sha256": hash_token("secret"), "active": True,
    }}))
    env_path = {**os.environ}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), "review", "--as", "vic", "--token", "secret"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**env_path,
             "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OPERATOR_REGISTRY": str(registry)},
    )
    assert result.returncode == 0, result.stderr

    denied = subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), "add", "block_ip", "--provider", "aws",
         "--as", "vic", "--token", "secret", "--reason", "r"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**env_path,
             "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
             "KRONAGENT_OPERATOR_REGISTRY": str(registry)},
    )
    assert denied.returncode == 4
