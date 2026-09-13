"""
The earn-trust dial, made real and audited.

Before this module, "graduating" an action class to autonomous execution meant
editing KRONAGENT_AUTO_EXECUTE_ALLOWLIST and restarting the process — a change with
zero record of who made it or why. For a platform whose entire safety case
rests on "nothing executes unattended until a human decided it should," that
gap was the biggest inconsistency in the system: the single most consequential
decision it makes had no audit trail.

AllowlistStore fixes that:
  * persisted to disk (JSON, atomic write) so it survives restarts without
    redeploying a new env var,
  * every add/remove is written to the hash-chained AuditLog as a "governance"
    stage record — the same forensic backbone containment and approval
    decisions already use,
  * read live by PolicyEngine on every decision — promoting or demoting an
    action class takes effect immediately, no restart.

Seeded on first use from KRONAGENT_AUTO_EXECUTE_ALLOWLIST (if set) so existing
deployments aren't silently reset to empty.

Autonomy is *earned*, so it also has to be *re-earned*. Without that, an
allowlist only ever grows: adding one more entry is always cheaper than
auditing whether the previous twelve still apply, and six months in nobody can
answer why `terminate_instance` was promoted or whether it has fired since.
That is firewall-rule sprawl and IAM-policy rot, applied to the one decision
this platform's safety case rests on. Three mechanisms close it:

  * **Expiry.** An entry may carry a TTL (`expires_at`). Past it, the entry is
    no longer auto-eligible and the class routes back to human approval. The
    read path (`is_allowed`) enforces this on its own, so the demotion is
    immediate and does not depend on any sweep having run; `expire_due()` is
    the sweep that *records* the lapse in the audit chain and clears the entry.
  * **Ownership.** `owner` is whoever is accountable for the entry *now* — the
    person asked when it is about to lapse, and the one who says yes again.
    That is a different fact from `promoted_by`/`promoted_at`, which record a
    decision someone made once and cannot un-make. Owners are reassigned as
    people change teams (`set_owner`); the promotion history never changes.
  * **Advance warning.** `warn_expiring()` tells an entry's owner, once, that
    their TTL is about to run out. Strictly a courtesy on top of the control:
    the entry lapses whether or not the message arrives, so a broken webhook
    can never extend anyone's authority. Its only job is to make sure the
    lapse is a decision someone declined to make, rather than a surprise
    discovered mid-incident.
  * **Last-fired tracking.** `record_fired()` is called when an entry actually
    authorizes an autonomous execution. An entry that never fires is standing
    authority with no benefit — the worst kind to leave lying around.
  * **Owner vacancy.** An owner who leaves the operator registry, is
    deactivated, loses PROMOTE, or loses access to the tenant can no longer
    renew anything — so the entry stops holding authority the moment that is
    true (`evaluate` refuses it at the gate), and the sweep
    `suspend_vacant_owners()` latches it as a suspension in the audit chain.
    A suspension is not a deletion: the entry stays, carrying its history,
    until someone with PROMOTE renews it or hands it to an owner who is still
    here. Reinstating the old owner does not lift it on its own — a quiet edit
    to a registry file is not a decision anyone made about autonomy.
  * **Pinned classification.** An entry records how the policy table
    classified its action on the day it was promoted. If that classification
    changes — in either direction — the entry stops holding and the sweep
    `suspend_reclassified()` latches it. A promotion was a decision about an
    action with particular properties; an action with different properties
    has not been decided about. The dangerous case is the quiet one: a class
    promoted while classified destructive (recorded, but inert behind the
    ceiling) would otherwise go live the day the table relaxed it. Only a
    renewal lifts this suspension, because only a renewal is a decision about
    the new classification.
  * **Review.** Everything a periodic review needs (who owns it, who promoted
    it, when, why, when it last fired, when it lapses) travels on the entry, so
    `promote.py review` can ask "does this still apply?" with the context in
    hand.

Why a TTL and not just a recurring review prompt: **a review fails open, an
expiry fails closed.** In a review, silence reads as approval — the entry
survives because nobody got to it, which is the exact failure being designed
against. An expiry inverts that: the entry lapses unless a named person
actively says yes again, so inattention withdraws autonomy instead of
extending it. The review command still exists, because someone has to be
handed the context to decide — but it is the prompt, not the control. This is
how badge permissions work on regulated physical sites: an owner and an
expiry, and it is the expiry that does the real work.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from pydantic import (
    AliasChoices, BaseModel, ConfigDict, Field, ValidationError, model_validator,
)

from .audit import AuditLog
from .classification import pinned_classification
from .identity import OwnerVacancy
from .schemas import ActionClass, AuditRecord, utcnow_iso

# An entry that has not fired in this long is flagged by `promote.py review`.
# Not enforced — a stale entry keeps working — because "unused" is a prompt to
# ask a human whether it is still wanted, not grounds for the system to decide.
DEFAULT_STALE_AFTER_DAYS = 30

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)


# Asks whether an owner may still hold an entry; None means yes. Built per
# tenant by `identity.owner_vacancy_checker`, injected so the store never reads
# the operator registry itself.
OwnerCheck = Callable[[str], Optional[OwnerVacancy]]

SUSPENDED_OWNER_VACANT = "owner_vacant"
SUSPENDED_RECLASSIFIED = "reclassified"


def _current_classification(action_class: str) -> Optional[dict]:
    """None for a class the taxonomy no longer knows: it grants nothing
    anyway, and there is no current classification to compare against."""
    try:
        return pinned_classification(ActionClass(action_class))
    except ValueError:
        return None


class OwnerNotInStandingError(ValueError):
    """Refused to name an owner who could not renew the entry they'd own."""

    def __init__(self, vacancy: OwnerVacancy) -> None:
        super().__init__(vacancy.reason)
        self.vacancy = vacancy


class DurationError(ValueError):
    """A TTL/window string that isn't of the form <integer><s|m|h|d|w>."""


def parse_duration(raw: str) -> timedelta:
    """'90d' -> 90 days. Suffix is required: a bare '90' is ambiguous, and
    guessing wrong on a governance TTL means autonomy lapses (or persists) for
    the wrong length of time."""
    match = _DURATION_RE.match(raw or "")
    if not match:
        raise DurationError(
            f"Invalid duration '{raw}'. Expected <number><unit>, unit one of "
            f"s/m/h/d/w — e.g. 90d, 12h, 2w."
        )
    amount = int(match.group(1))
    if amount <= 0:
        raise DurationError(f"Invalid duration '{raw}': must be greater than zero.")
    return timedelta(seconds=amount * _DURATION_UNITS[match.group(2).lower()])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse a stored ISO timestamp, tolerating hand-edited values. A naive
    timestamp is read as UTC; an unparseable one yields None, which every
    caller treats as 'no reliable time here' rather than crashing the read
    path that gates containment."""
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class AllowlistEntry(BaseModel):
    """One promoted action class.

    Two different facts about people live here and must not be collapsed:
    `promoted_by`/`promoted_at` are immutable history — a decision someone made
    on a date, which no later event changes — while `owner` is who is
    accountable for the entry today and gets asked to renew it. The promoter
    may have left the company; the owner is by definition someone who hasn't.

    `promoted_by`/`promoted_at` also load from the older `added_by`/`added_at`
    keys, so a store written before ownership existed reads without migration.
    """

    model_config = ConfigDict(populate_by_name=True)

    action_class: str
    promoted_by: str = Field(validation_alias=AliasChoices("promoted_by", "added_by"))
    promoted_at: str = Field(default_factory=utcnow_iso,
                             validation_alias=AliasChoices("promoted_at", "added_at"))
    reason: str
    # Defaults to the promoter: whoever promoted it owns it until they hand it
    # over. An entry with no owner at all would be exactly the orphan this
    # field exists to prevent.
    owner: str = ""
    # None = no TTL: standing authority until an operator demotes it. Explicit,
    # not the absence of a decision — `promote.py review` reports it as such.
    expires_at: Optional[str] = None
    # Set by record_fired() when this entry authorizes an autonomous execution.
    last_fired_at: Optional[str] = None
    fire_count: int = 0
    # Set when something other than the clock withdrew this entry's authority
    # (today: its owner left). The entry is kept so the fix — renew, or hand it
    # to someone still here — has the history in front of it.
    suspended_at: Optional[str] = None
    suspended_trigger: Optional[str] = None
    suspended_reason: Optional[str] = None
    # How the policy table classified this action when it was promoted (or
    # last renewed). None on entries written before pinning existed: those are
    # not checked, and review says so, until a renewal pins them.
    classification: Optional[dict] = None

    @model_validator(mode="after")
    def _default_owner_to_promoter(self) -> "AllowlistEntry":
        if not self.owner:
            self.owner = self.promoted_by
        return self

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        expiry = parse_ts(self.expires_at)
        if expiry is None:
            # No TTL, or a corrupt one. A corrupt expiry must not read as
            # "never expires" — that would turn a typo into permanent
            # autonomy — so fail closed and treat it as already lapsed.
            return bool(self.expires_at)
        return (now or _utcnow()) >= expiry

    @property
    def is_suspended(self) -> bool:
        return self.suspended_at is not None

    def classification_drift(self) -> Optional[str]:
        """How this action's classification has changed since it was pinned,
        or None if it has not (or was never pinned)."""
        if self.classification is None:
            return None
        current = _current_classification(self.action_class)
        if current is None or current == self.classification:
            return None
        changes = [
            f"{field} {self.classification.get(field)!r} → {current[field]!r}"
            for field in sorted(current)
            if self.classification.get(field) != current[field]
        ]
        return ("the policy table reclassified this action since it was promoted: "
                + ", ".join(changes))

    def is_stale(self, *, after_days: int = DEFAULT_STALE_AFTER_DAYS,
                 now: Optional[datetime] = None) -> bool:
        """True if this entry has not authorized an execution in `after_days`.
        An entry that has never fired is stale once it is itself that old —
        a promotion made yesterday hasn't had a chance yet."""
        reference = parse_ts(self.last_fired_at) or parse_ts(self.promoted_at)
        if reference is None:
            return False
        return (now or _utcnow()) - reference >= timedelta(days=after_days)


class AllowlistStore:
    def __init__(self, path: str, *, seed: frozenset[str] = frozenset()) -> None:
        self._path = path
        if not os.path.exists(self._path) and seed:
            self._write_all({
                ac: AllowlistEntry(
                    action_class=ac, promoted_by="system",
                    reason="seeded from KRONAGENT_AUTO_EXECUTE_ALLOWLIST",
                    classification=_current_classification(ac),
                ).model_dump()
                for ac in seed
            })

    # --- persistence (same atomic-replace pattern as ApprovalStore) ---
    def _read_all(self) -> dict[str, dict]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return {}

    def _write_all(self, data: dict[str, dict]) -> None:
        directory = os.path.dirname(os.path.abspath(self._path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # --- read path used by PolicyEngine on every decision ---
    def evaluate(
        self, action_class: ActionClass, *, now: Optional[datetime] = None,
        owner_check: Optional[OwnerCheck] = None,
    ) -> tuple[bool, Optional[str]]:
        """Whether this class is authorized for autonomy right now, and if an
        entry exists but does not hold, why not.

        Everything that withdraws authority is enforced here, at the gate, and
        none of it waits for a sweep: an expired TTL, a latched suspension, and
        an owner who is no longer in standing. The sweeps only record what this
        already refuses. `(False, None)` means there is simply no entry.
        """
        raw = self._read_all().get(action_class.value)
        if raw is None:
            return False, None
        try:
            entry = AllowlistEntry.model_validate(raw)
        except ValidationError:
            return False, "allowlist entry is unreadable"  # grants nothing
        if entry.is_expired(now):
            return False, f"allowlist entry expired at {entry.expires_at}"
        if entry.is_suspended:
            return False, f"allowlist entry suspended: {entry.suspended_reason}"
        drift = entry.classification_drift()
        if drift is not None:
            return False, f"allowlist entry no longer applies: {drift}"
        if owner_check is not None:
            vacancy = owner_check(entry.owner)
            if vacancy is not None:
                return False, f"allowlist entry has no owner in standing: {vacancy.reason}"
        return True, None

    def is_allowed(
        self, action_class: ActionClass, *, now: Optional[datetime] = None,
        owner_check: Optional[OwnerCheck] = None,
    ) -> bool:
        return self.evaluate(action_class, now=now, owner_check=owner_check)[0]

    def list(self) -> list[AllowlistEntry]:
        """Every entry on file, expired ones included — `promote.py review`
        needs to see a lapsed entry to ask whether it should be renewed. Use
        `active()` for the set that is actually authorizing autonomy."""
        entries = []
        for value in self._read_all().values():
            try:
                entries.append(AllowlistEntry.model_validate(value))
            except ValidationError:
                # A malformed entry grants nothing (is_allowed refuses it too),
                # so skipping it here is safe rather than convenient.
                continue
        return sorted(entries, key=lambda e: e.action_class)

    def active(self, *, now: Optional[datetime] = None) -> list[AllowlistEntry]:
        """Entries neither expired nor suspended. Owner standing is not applied
        here — it needs a directory — so the policy gate remains the authority
        on what actually executes."""
        return [e for e in self.list() if not e.is_expired(now) and not e.is_suspended]

    def expired(self, *, now: Optional[datetime] = None) -> list[AllowlistEntry]:
        return [e for e in self.list() if e.is_expired(now)]

    # --- write path: operator-driven, always audited ---
    async def add(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None, expires_in: Optional[timedelta] = None,
        owner: Optional[str] = None, now: Optional[datetime] = None,
        owner_check: Optional[OwnerCheck] = None,
    ) -> AllowlistEntry:
        """Promote a class, or renew it. A renewal is a fresh decision, so it
        also lifts any suspension — but only onto an owner who is in standing:
        with `owner_check`, naming (or inheriting) an owner who has left raises
        `OwnerNotInStandingError` and writes nothing, since the entry would be
        suspended again on the next sweep with nobody to ask."""
        expires_at = ((now or _utcnow()) + expires_in).isoformat() if expires_in else None
        entry = AllowlistEntry(
            action_class=action_class.value, promoted_by=by, reason=reason,
            expires_at=expires_at, owner=owner or by,
            # Pinned afresh on every renewal: renewing is the decision about
            # the action as it is classified today.
            classification=pinned_classification(action_class),
        )
        data = self._read_all()
        previous = data.get(action_class.value)
        # Re-promoting the same class is the renewal path: it takes a fresh
        # reason and a fresh TTL, which is exactly the "re-earn it" motion.
        # Carry the firing history across so a renewal doesn't reset the
        # evidence of whether the entry was ever used, and keep the existing
        # owner unless this renewal names a new one — renewing on someone's
        # behalf shouldn't quietly move the accountability to the renewer.
        if previous:
            entry.last_fired_at = previous.get("last_fired_at")
            entry.fire_count = previous.get("fire_count") or 0
            if not owner:
                entry.owner = previous.get("owner") or by
        if owner_check is not None:
            vacancy = owner_check(entry.owner)
            if vacancy is not None:
                raise OwnerNotInStandingError(vacancy)
        data[action_class.value] = entry.model_dump()
        self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_add", "action_class": action_class.value,
                "by": by, "reason": reason, "already_present": previous is not None,
                "expires_at": expires_at, "owner": entry.owner,
                "lifted_suspension": (previous or {}).get("suspended_reason"),
                "classification": entry.classification,
                **(actor_fields or {}),
            },
        ))
        return entry

    async def set_owner(
        self, action_class: ActionClass, *, owner: str, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None, owner_check: Optional[OwnerCheck] = None,
    ) -> Optional[AllowlistEntry]:
        """Hand an entry to a new accountable owner.

        People change teams; the decision they made in March does not. So this
        moves `owner` and leaves `promoted_by`/`promoted_at`/`reason` exactly as
        they were — the history stays true, and there is still a named person
        to ask at renewal time. Audited like any other governance change, since
        it changes who can say yes.

        Handing an entry to an owner in standing lifts an owner-vacancy
        suspension — that is the fix for exactly that problem — and nothing
        else: a reassignment answers "who is accountable", not "does this still
        apply". With `owner_check`, reassigning to someone not in standing
        raises `OwnerNotInStandingError` and writes nothing.
        """
        if owner_check is not None:
            vacancy = owner_check(owner)
            if vacancy is not None:
                raise OwnerNotInStandingError(vacancy)
        data = self._read_all()
        raw = data.get(action_class.value)
        previous_owner = (raw or {}).get("owner") or (raw or {}).get("promoted_by") or ""
        lifted = None
        if raw is not None:
            raw["owner"] = owner
            if raw.get("suspended_trigger") == SUSPENDED_OWNER_VACANT:
                lifted = raw.get("suspended_reason")
                raw["suspended_at"] = raw["suspended_trigger"] = raw["suspended_reason"] = None
            self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_reassign", "action_class": action_class.value,
                "by": by, "reason": reason, "owner": owner,
                "previous_owner": previous_owner, "existed": raw is not None,
                "lifted_suspension": lifted,
                **(actor_fields or {}),
            },
        ))
        return AllowlistEntry.model_validate(raw) if raw is not None else None

    async def remove(
        self, action_class: ActionClass, *, by: str, reason: str, audit: AuditLog,
        actor_fields: Optional[dict] = None,
    ) -> bool:
        data = self._read_all()
        existed = data.pop(action_class.value, None) is not None
        if existed:
            self._write_all(data)
        await audit.record(AuditRecord(
            finding_id="_governance", stage="governance",
            payload={
                "decision": "allowlist_remove", "action_class": action_class.value,
                "by": by, "reason": reason, "existed": existed,
                **(actor_fields or {}),
            },
        ))
        return existed

    async def expire_due(
        self, *, audit: AuditLog, now: Optional[datetime] = None,
    ) -> list[AllowlistEntry]:
        """Clear entries whose TTL has lapsed, recording each in the audit chain.

        A lapse is a governance event with no human behind it, so it gets the
        same treatment as a demotion an operator typed: its own hash-chained
        record, carrying the promotion it reverses (who, when, why) and whether
        the entry ever actually fired. Six months on, that record — not
        somebody's memory — is what says the authority ended and what it was
        for.

        Idempotent: the entry is gone afterwards, so one lapse produces exactly
        one record no matter how many callers sweep.
        """
        now = now or _utcnow()
        data = self._read_all()
        lapsed = [e for e in self.list() if e.is_expired(now)]
        if not lapsed:
            return []
        for entry in lapsed:
            data.pop(entry.action_class, None)
        self._write_all(data)
        for entry in lapsed:
            await audit.record(AuditRecord(
                finding_id="_governance", stage="governance",
                payload={
                    "decision": "allowlist_expired", "action_class": entry.action_class,
                    "by": "system", "reason": "TTL elapsed — autonomy not renewed",
                    "expires_at": entry.expires_at,
                    # The owner is who to ask about renewing; the promoter is
                    # who decided it in the first place. Both, so the record
                    # answers "who let this lapse" and "whose call was it".
                    "owner": entry.owner,
                    "promoted_by": entry.promoted_by, "promoted_at": entry.promoted_at,
                    "promotion_reason": entry.reason,
                    "last_fired_at": entry.last_fired_at, "fire_count": entry.fire_count,
                    "identity_verified": False, "auth_method": "system",
                },
            ))
        return lapsed

    async def suspend_vacant_owners(
        self, *, audit: AuditLog, owner_check: Optional[OwnerCheck],
        now: Optional[datetime] = None,
    ) -> list[tuple[AllowlistEntry, OwnerVacancy]]:
        """Latch a suspension on every entry whose owner has definitively left.

        The gate already refuses these; this makes the withdrawal a recorded
        governance event and makes it stick. Without the latch, autonomy would
        come back the moment someone re-added a name to the registry file —
        an edit nobody audits, standing in for a decision nobody made.

        A vacancy that is not definitive (the registry could not be read) is
        refused at the gate but never latched: a broken file has not made
        anyone leave. Idempotent — an already-suspended entry is skipped, so
        one departure produces exactly one record per entry.
        """
        if owner_check is None:
            return []
        now = now or _utcnow()
        data = self._read_all()
        suspended = []
        for entry in self.list():
            if entry.is_expired(now) or entry.is_suspended:
                continue
            vacancy = owner_check(entry.owner)
            if vacancy is None or not vacancy.definitive:
                continue
            raw = data[entry.action_class]
            raw["suspended_at"] = now.isoformat()
            raw["suspended_trigger"] = SUSPENDED_OWNER_VACANT
            raw["suspended_reason"] = vacancy.reason
            suspended.append((AllowlistEntry.model_validate(raw), vacancy))
        if not suspended:
            return []
        self._write_all(data)
        for entry, vacancy in suspended:
            await audit.record(AuditRecord(
                finding_id="_governance", stage="governance",
                payload={
                    "decision": "allowlist_suspended", "action_class": entry.action_class,
                    "trigger": SUSPENDED_OWNER_VACANT,
                    "by": "system", "reason": vacancy.reason,
                    "owner": entry.owner,
                    "promoted_by": entry.promoted_by, "promoted_at": entry.promoted_at,
                    "promotion_reason": entry.reason, "expires_at": entry.expires_at,
                    "last_fired_at": entry.last_fired_at, "fire_count": entry.fire_count,
                    "identity_verified": False, "auth_method": "system",
                },
            ))
        return suspended

    async def suspend_reclassified(
        self, *, audit: AuditLog, now: Optional[datetime] = None,
    ) -> list[tuple[AllowlistEntry, str]]:
        """Latch a suspension on every entry whose action has been reclassified.

        Same contract as `suspend_vacant_owners`: the gate already refuses
        these, and this makes it a recorded event that sticks. Without the
        latch, reverting the table would silently restore autonomy that was
        never re-decided. Idempotent — suspended entries are skipped.
        """
        now = now or _utcnow()
        data = self._read_all()
        suspended = []
        for entry in self.list():
            if entry.is_expired(now) or entry.is_suspended:
                continue
            drift = entry.classification_drift()
            if drift is None:
                continue
            raw = data[entry.action_class]
            raw["suspended_at"] = now.isoformat()
            raw["suspended_trigger"] = SUSPENDED_RECLASSIFIED
            raw["suspended_reason"] = drift
            suspended.append((AllowlistEntry.model_validate(raw), drift))
        if not suspended:
            return []
        self._write_all(data)
        for entry, drift in suspended:
            await audit.record(AuditRecord(
                finding_id="_governance", stage="governance",
                payload={
                    "decision": "allowlist_suspended", "action_class": entry.action_class,
                    "trigger": SUSPENDED_RECLASSIFIED,
                    "by": "system", "reason": drift,
                    "pinned_classification": entry.classification,
                    "current_classification": _current_classification(entry.action_class),
                    "owner": entry.owner,
                    "promoted_by": entry.promoted_by, "promoted_at": entry.promoted_at,
                    "promotion_reason": entry.reason, "expires_at": entry.expires_at,
                    "last_fired_at": entry.last_fired_at, "fire_count": entry.fire_count,
                    "identity_verified": False, "auth_method": "system",
                },
            ))
        return suspended

    def expiring_within(
        self, window: timedelta, *, now: Optional[datetime] = None,
    ) -> list[AllowlistEntry]:
        """Live entries whose TTL lapses inside `window`, soonest first.

        Only entries that still hold authority: an already-lapsed one has
        nothing left to warn about, and one with no TTL never lapses.
        """
        now = now or _utcnow()
        due = []
        for entry in self.active(now=now):
            expiry = parse_ts(entry.expires_at)
            if expiry is not None and expiry - now <= window:
                due.append((expiry, entry))
        return [entry for _, entry in sorted(due, key=lambda pair: pair[0])]

    def warned_expiries(self, audit: AuditLog) -> set[tuple[str, str]]:
        """(action_class, expires_at) pairs already warned about.

        Keyed on the expiry itself, not the class, so renewing an entry arms a
        fresh warning for its new deadline while a daily cron over the same
        deadline stays silent after the first notice.
        """
        return {
            (r["payload"].get("action_class", ""), r["payload"].get("expires_at") or "")
            for r in audit.records()
            if r.get("stage") == "governance"
            and r.get("payload", {}).get("decision") == "allowlist_expiry_warning"
        }

    async def warn_expiring(
        self, *, audit: AuditLog, within: timedelta,
        notify: Optional[Callable[[AllowlistEntry], bool]] = None,
        now: Optional[datetime] = None,
    ) -> list[tuple[AllowlistEntry, bool]]:
        """Warn each owner once that their entry is about to lapse.

        The TTL is deliberately fail-closed — an entry lapses whether or not
        anyone was told — so this is a courtesy, not a control, and it is built
        so that failing to deliver it cannot extend anyone's authority. The
        warning is recorded in the audit chain even when no chat transport is
        configured or the send fails, which is also what makes it exactly-once:
        the record *is* the delivery state.

        `notify` is injected rather than imported so the store stays free of
        transport concerns and tests never touch the network. Returns
        (entry, notified) pairs for everything warned this run.
        """
        now = now or _utcnow()
        already = self.warned_expiries(audit)
        warned = []
        for entry in self.expiring_within(within, now=now):
            if (entry.action_class, entry.expires_at or "") in already:
                continue
            notified = False
            if notify is not None:
                try:
                    notified = bool(notify(entry))
                except Exception:
                    # A broken webhook must not stop the remaining warnings, and
                    # must not look like a delivered one.
                    notified = False
            expiry = parse_ts(entry.expires_at)
            await audit.record(AuditRecord(
                finding_id="_governance", stage="governance",
                payload={
                    "decision": "allowlist_expiry_warning",
                    "action_class": entry.action_class,
                    "by": "system",
                    "reason": (f"expires {entry.expires_at} — owner {entry.owner} notified"
                               if notified else
                               f"expires {entry.expires_at} — owner {entry.owner} NOT reachable "
                               f"(no chat transport or delivery failed)"),
                    "owner": entry.owner, "expires_at": entry.expires_at,
                    "seconds_remaining": int((expiry - now).total_seconds()) if expiry else None,
                    "notified": notified,
                    "promoted_by": entry.promoted_by, "promoted_at": entry.promoted_at,
                    "promotion_reason": entry.reason,
                    "last_fired_at": entry.last_fired_at, "fire_count": entry.fire_count,
                    "identity_verified": False, "auth_method": "system",
                },
            ))
            warned.append((entry, notified))
        return warned

    def record_fired(self, action_class: ActionClass, *, now: Optional[datetime] = None) -> None:
        """Note that this entry authorized an autonomous execution.

        Not audited: the execution itself already lands in the audit chain as a
        containment record, and mirroring every firing into the governance
        stage would bury the promote/demote/expire decisions that stage exists
        to make findable. This is a usage counter for review, not evidence.
        """
        data = self._read_all()
        raw = data.get(action_class.value)
        if raw is None:
            return
        raw["last_fired_at"] = (now or _utcnow()).isoformat()
        raw["fire_count"] = (raw.get("fire_count") or 0) + 1
        self._write_all(data)
