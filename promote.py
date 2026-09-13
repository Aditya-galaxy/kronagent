#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent governance CLI — the earn-trust dial.

Promotes or demotes an action class between "always needs human approval" and
"executes autonomously when auto-eligible." This is the single most
consequential decision the platform's operators make — it's what decides
whether a class of action runs unattended against production — so every
change here is written to the hash-chained audit log with who made it and why,
same as an approval decision.

    python3 promote.py list
    python3 promote.py add      disable_access_key --by alice --reason "30 days incident-free, low blast radius"
    python3 promote.py add      disable_access_key --by alice --reason "..." --expires-in 90d --owner dana
    python3 promote.py remove   disable_access_key --by alice --reason "false-positive rate too high"
    python3 promote.py reassign disable_access_key --to erin --by alice --reason "dana moved to platform"
    python3 promote.py review   --by alice
    python3 promote.py warn-expiring --within 14d          # for cron; warns owners once each

A promotion only has effect for action classes the policy engine already
classifies AUTO_ELIGIBLE (reversible, single-resource, non-destructive) — see
policy.py. Promoting a destructive or wide-blast-radius class is accepted (the
store doesn't second-guess an operator) but has no effect: the policy engine's
own classification is the hard ceiling, so an operator error here degrades to
"still requires approval," not "now executes something dangerous."

Trust is earned one action class at a time — and, with `--expires-in`, it is
re-earned on a clock. A promotion with a TTL lapses on its own back to "human
approval required" unless an operator renews it (re-run `add` with a fresh
reason), and the lapse is recorded in the audit chain like any other
governance decision. The TTL, not the review, is what does the work: a review
fails open (silence reads as approval) while an expiry fails closed (the entry
lapses unless a named person actively says yes again).

That named person is the entry's `--owner`, which defaults to whoever promoted
it. Owner and promoter are different facts and are stored separately: the
promoter made a decision on a date that nothing later changes, while the owner
is who is accountable *now* and gets asked at renewal time — reassignable with
`reassign` as people change teams.

`review` is the prompt, not the control: it prints every entry with its owner,
the promotion reason, who promoted it, and when it last actually fired, so
whoever is deciding has the context in hand — and it records that the review
happened, and who did it. `warn-expiring` is the same idea pushed rather than
pulled: run it from cron and each owner is told once, ahead of time, that their
entry is about to lapse. Neither can keep an entry alive; only an operator
re-running `add` with a current reason can do that.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

from kronagent.allowlist import (
    DEFAULT_STALE_AFTER_DAYS, AllowlistEntry, AllowlistStore, DurationError,
    OwnerNotInStandingError, parse_duration, parse_ts,
)
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.identity import (
    DEFAULT_TENANT, AuthContext, AuthorizationError, Permission, owner_vacancy_checker,
    resolve_actor,
)
from kronagent.policy import PolicyEngine
from kronagent.schemas import ActionClass, AuditRecord


def _resolve(settings: Settings, audit: AuditLog, args: argparse.Namespace,
             required: Permission) -> AuthContext:
    """Resolve + authorize the acting operator; audit + exit(4) on failure."""
    try:
        return resolve_actor(
            registry_path=settings.operator_registry_path,
            required=required,
            by=getattr(args, "by", None),
            operator_id=getattr(args, "as_operator", None),
            token=getattr(args, "token", None) or os.getenv("KRONAGENT_OPERATOR_TOKEN"),
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_uri=settings.oidc_jwks_uri,
            oidc_verify_signature=settings.oidc_verify_signature,
            oidc_roles_claim=settings.oidc_roles_claim,
        )
    except AuthorizationError as exc:
        asyncio.run(audit.record(AuditRecord(
            finding_id="_governance", stage="access_denied",
            payload={"command": args.command, "required": required.value,
                     "action_class": getattr(args, "action_class", None),
                     "operator_id": getattr(args, "as_operator", None) or getattr(args, "by", None),
                     "error": str(exc)},
        )))
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        raise SystemExit(4)


def _parse_action_class(raw: str) -> ActionClass:
    try:
        return ActionClass(raw)
    except ValueError:
        valid = ", ".join(ac.value for ac in ActionClass)
        print(f"Unknown action class '{raw}'. Valid values: {valid}", file=sys.stderr)
        raise SystemExit(2)


def _parse_window(raw: str, flag: str) -> timedelta:
    try:
        return parse_duration(raw)
    except DurationError as exc:
        print(f"{flag}: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _humanize(delta: timedelta) -> str:
    """A coarse, unambiguous magnitude. Governance review is a days-and-weeks
    conversation, so anything finer is noise. Rounded rather than truncated:
    a 90-day TTL reading back as '89d' looks like an off-by-one in the thing
    an operator is being asked to trust."""
    seconds = abs(delta.total_seconds())
    if seconds < 3600:
        return f"{round(seconds / 60)}m"
    if seconds < 86400:
        return f"{round(seconds / 3600)}h"
    return f"{round(seconds / 86400)}d"


def _ago(ts: Optional[str], now: datetime) -> str:
    parsed = parse_ts(ts)
    return "unknown" if parsed is None else f"{_humanize(now - parsed)} ago"


def _expiry_phrase(entry: AllowlistEntry, now: datetime) -> str:
    if not entry.expires_at:
        return "never (no TTL — standing authority until demoted)"
    parsed = parse_ts(entry.expires_at)
    if parsed is None:
        return f"{entry.expires_at} (UNREADABLE — treated as expired)"
    if entry.is_expired(now):
        return f"{entry.expires_at} (EXPIRED {_humanize(now - parsed)} ago)"
    return f"{entry.expires_at} (in {_humanize(parsed - now)})"


def _fired_phrase(entry: AllowlistEntry, now: datetime) -> str:
    if not entry.last_fired_at:
        return f"NEVER — promoted {_ago(entry.promoted_at, now)}, has authorized nothing since"
    plural = "" if entry.fire_count == 1 else "s"
    return f"{entry.last_fired_at} ({_ago(entry.last_fired_at, now)}, {entry.fire_count} time{plural})"


def _is_auto_eligible(policy: PolicyEngine, action_class: str) -> Optional[bool]:
    """None for a class the taxonomy no longer knows — a renamed or removed
    action, or a hand-edited store. It grants nothing (the policy engine can
    never propose it), but reporting has to survive finding one."""
    try:
        return policy.is_auto_eligible(ActionClass(action_class))
    except ValueError:
        return None


def _owner_check(settings: Settings):
    # This CLI governs the default tenant's store (settings.allowlist_store_path).
    return owner_vacancy_checker(settings.operator_registry_path, DEFAULT_TENANT)


def _standing_flags(e: AllowlistEntry, owner_check, now: datetime) -> list[str]:
    """Why an unexpired entry grants nothing despite being on file."""
    if e.is_expired(now):
        return []
    if e.is_suspended:
        return [f"SUSPENDED — {e.suspended_reason}"]
    drift = e.classification_drift()
    if drift is not None:
        return [f"RECLASSIFIED — {drift}"]
    vacancy = owner_check(e.owner) if owner_check else None
    if vacancy is not None:
        return [f"OWNER NOT IN STANDING — {vacancy.reason}"]
    return []


def _refuse_owner(exc: OwnerNotInStandingError) -> int:
    print(f"REFUSED: {exc}. An entry can only be owned by an active operator with the "
          f"promote permission on this tenant — someone who could renew it. "
          f"Name one with --owner.", file=sys.stderr)
    return 2


def cmd_list(store: AllowlistStore, settings: Settings) -> int:
    entries = store.list()
    if not entries:
        print("Allowlist is EMPTY — every action requires human approval.")
        return 0
    policy = PolicyEngine(settings, store)
    owner_check = _owner_check(settings)
    now = datetime.now().astimezone()
    print("Auto-execute allowlist:")
    for e in entries:
        eligible = _is_auto_eligible(policy, e.action_class)
        flags = [f"⚠ {flag}" for flag in _standing_flags(e, owner_check, now)]
        if eligible is None:
            flags.append("⚠ UNKNOWN action class — not in the taxonomy, grants nothing")
        elif not eligible:
            flags.append("⚠ NOT auto-eligible (policy engine overrides — still requires approval)")
        if e.is_expired(now):
            flags.append("⚠ EXPIRED — requires human approval again until renewed")
        elif e.is_stale(now=now):
            flags.append("⚠ STALE — has not fired recently (see `promote.py review`)")
        suffix = "".join(f"  {f}" for f in flags)
        print(f"  {e.action_class:32} owned by {e.owner}{suffix}")
        print(f"      promoted by {e.promoted_by} at {e.promoted_at}")
        print(f"      reason: {e.reason}")
        print(f"      expires: {_expiry_phrase(e, now)}")
        print(f"      last fired: {_fired_phrase(e, now)}")
    return 0


def _lapses_since_last_review(audit_path: str, now: datetime) -> list[dict]:
    """Entries that expired since anyone last ran a review.

    A lapse removes the entry, so without this the only trace is one line on
    stderr of whichever command happened to trigger the sweep — which nobody
    was watching. The audit log already recorded it; this surfaces it at the
    next review, where the decision to renew or let it go actually gets made.
    Falls back to a 90-day window when there is no previous review.
    """
    governance = [r for r in AuditLog.read_records(audit_path)
                  if r.get("stage") == "governance"]
    reviews = [parse_ts(r.get("ts")) for r in governance
               if r.get("payload", {}).get("decision") == "allowlist_review"]
    cutoff = max((ts for ts in reviews if ts), default=now - timedelta(days=90))
    return [r for r in governance
            if r.get("payload", {}).get("decision") == "allowlist_expired"
            and (parse_ts(r.get("ts")) or now) > cutoff]


def cmd_review(store: AllowlistStore, audit: AuditLog, settings: Settings,
               actor: AuthContext, args: argparse.Namespace) -> int:
    """The periodic re-earn-it pass.

    Everything here is already in the audit log; nothing surfaced it. An
    operator asking "does this entry still apply?" needs the original reason,
    who staked their name on it, how long it has stood, and whether it has ever
    actually fired — on one screen, next to the command that renews or revokes
    it. Reviewing is also itself recorded, so "when did anyone last look at
    this allowlist" has an answer that isn't a guess.
    """
    stale_after = _parse_window(args.stale_after, "--stale-after")
    expiring_within = _parse_window(args.expiring_within, "--expiring-within")
    stale_days = max(1, int(stale_after.total_seconds() // 86400))

    entries = store.list()
    policy = PolicyEngine(settings, store)
    owner_check = _owner_check(settings)
    now = datetime.now().astimezone()

    flagged: dict[str, list[str]] = {}
    for e in entries:
        reasons = []
        if not e.is_expired(now):
            if e.is_suspended:
                reasons.append("suspended")
            elif e.classification_drift() is not None:
                reasons.append("reclassified")
            elif owner_check is not None and owner_check(e.owner) is not None:
                reasons.append("owner not in standing")
        if e.classification is None and _is_auto_eligible(policy, e.action_class) is not None:
            # Predates pinning: a reclassification would go unnoticed for it.
            reasons.append("classification not pinned — renew to pin it")
        if e.is_expired(now):
            reasons.append("expired")
        else:
            expiry = parse_ts(e.expires_at)
            if expiry is not None and expiry - now <= expiring_within:
                reasons.append("expiring soon")
            if e.expires_at is None:
                reasons.append("no TTL")
        # A promotion made yesterday hasn't had a chance to fire yet; flagging
        # it would train operators to scroll past the flag that matters.
        if e.is_stale(after_days=stale_days, now=now):
            reasons.append("never fired" if not e.last_fired_at else "stale")
        eligible = _is_auto_eligible(policy, e.action_class)
        if eligible is None:
            reasons.append("unknown action class")
        elif not eligible:
            reasons.append("not auto-eligible")
        if reasons:
            flagged[e.action_class] = reasons

    print(f"Allowlist review — {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, "
          f"reviewed by {actor.label} at {now.isoformat(timespec='seconds')}")
    print(f"(stale threshold: {args.stale_after}; expiry warning window: {args.expiring_within})")
    if owner_check is None and entries:
        print("(owner standing NOT checked — no operator registry, so nothing notices an owner "
              "leaving)")
    if not entries:
        print("\nAllowlist is EMPTY — every action requires human approval. Nothing to review.")
    for e in entries:
        reasons = flagged.get(e.action_class, [])
        marker = "⚠" if reasons else "✓"
        # Not labelling owner != promoted_by as "reassigned": promoting on
        # someone else's behalf (`add --owner dana`) produces exactly that shape
        # at promotion time, so the claim was false on every such entry. A real
        # reassignment is an audit event, not a property of the entry.
        print(f"\n{marker} {e.action_class}")
        print(f"    owner        {e.owner} — ask them to renew")
        print(f"    promoted by  {e.promoted_by} at {e.promoted_at} ({_ago(e.promoted_at, now)})")
        print(f"    reason       {e.reason}")
        print(f"    expires      {_expiry_phrase(e, now)}")
        print(f"    last fired   {_fired_phrase(e, now)}")
        for flag in _standing_flags(e, owner_check, now):
            print(f"    STANDING     {flag}")
        if reasons:
            print(f"    ATTENTION    {', '.join(reasons)}")
            print(f"    renew:  python3 promote.py add {e.action_class} "
                  f"--by <you> --reason \"<why it still applies>\" --expires-in 90d")
            print(f"    revoke: python3 promote.py remove {e.action_class} "
                  f"--by <you> --reason \"<why it no longer applies>\"")

    lapsed = _lapses_since_last_review(settings.audit_log_path, now)
    if lapsed:
        print(f"\nLapsed since the last review ({len(lapsed)}) — autonomy already withdrawn; "
              f"renew only if it still applies:")
        for record in lapsed:
            p = record["payload"]
            fired = (f"fired {p.get('fire_count') or 0}x, last {_ago(p.get('last_fired_at'), now)}"
                     if p.get("last_fired_at") else "never fired")
            print(f"\n  {p['action_class']} — expired {p.get('expires_at')}")
            print(f"      owned by {p.get('owner') or p.get('promoted_by')} — the renew-or-drop "
                  f"call is theirs")
            print(f"      promoted by {p.get('promoted_by')} at {p.get('promoted_at')}: "
                  f"{p.get('promotion_reason')}")
            print(f"      {fired}")
            print(f"      renew:  python3 promote.py add {p['action_class']} "
                  f"--by <you> --reason \"<why it still applies>\" --expires-in 90d")

    noun, verb = ("entry", "needs") if len(entries) == 1 else ("entries", "need")
    print(f"\n{len(flagged)} of {len(entries)} {noun} {verb} a decision.")

    asyncio.run(audit.record(AuditRecord(
        finding_id="_governance", stage="governance",
        payload={
            "decision": "allowlist_review", "by": actor.operator_id,
            "reason": (f"periodic allowlist review — {len(flagged)} of {len(entries)} "
                       f"entries flagged for a decision"),
            "entries": len(entries), "flagged": sorted(flagged),
            "flag_reasons": flagged,
            # Who has to act, not just what was flagged — the log should answer
            # "who was on the hook after this review" without a second lookup.
            "flagged_owners": {e.action_class: e.owner for e in entries
                               if e.action_class in flagged},
            "lapsed_since_last_review": [r["payload"]["action_class"] for r in lapsed],
            "stale_after": args.stale_after, "expiring_within": args.expiring_within,
            **actor.audit_fields(),
        },
    )))

    # An unreviewed allowlist is the failure mode this command exists to catch,
    # so `--strict` lets a scheduled run fail loudly instead of printing into a
    # log nobody reads.
    return 3 if (flagged and args.strict) else 0


def cmd_add(store: AllowlistStore, audit: AuditLog, settings: Settings,
            actor: AuthContext, args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    expires_in = _parse_window(args.expires_in, "--expires-in") if args.expires_in else None
    policy = PolicyEngine(settings, store)
    renewal = any(e.action_class == ac.value for e in store.list())
    try:
        entry = asyncio.run(store.add(ac, by=actor.operator_id, reason=args.reason, audit=audit,
                                      actor_fields=actor.audit_fields(), expires_in=expires_in,
                                      owner=args.owner, owner_check=_owner_check(settings)))
    except OwnerNotInStandingError as exc:
        return _refuse_owner(exc)
    verb = "Renewed" if renewal else "Promoted"
    print(f"{verb} {entry.action_class} to autonomous execution (by {actor.label}).")
    print(f"  Owner: {entry.owner} — the one asked to renew it, and the one who says yes again.")
    if entry.expires_at:
        print(f"  Expires {entry.expires_at} ({args.expires_in}) — after that it requires human "
              f"approval again until an operator renews it.")
    else:
        print("  No expiry — this is standing authority until someone demotes it. Consider "
              "--expires-in (e.g. 90d) so the decision has to be re-made rather than inherited.")
    if not policy.is_auto_eligible(ac):
        print(f"  ⚠ WARNING: {ac.value} is classified destructive or wide-blast-radius by the "
              f"policy engine — it will still route to human approval regardless of this "
              f"allowlist entry. The promotion is recorded but has no effect.")
    return 0


def cmd_remove(store: AllowlistStore, audit: AuditLog, actor: AuthContext,
               args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    existed = asyncio.run(store.remove(ac, by=actor.operator_id, reason=args.reason, audit=audit,
                                       actor_fields=actor.audit_fields()))
    if existed:
        print(f"Demoted {ac.value} (by {actor.label}) — now requires human approval again.")
    else:
        print(f"{ac.value} was not on the allowlist (no-op, still recorded for the audit trail).")
    return 0


def cmd_warn_expiring(store: AllowlistStore, audit: AuditLog, settings: Settings,
                      args: argparse.Namespace) -> int:
    """Tell owners, once, that their grant of autonomy is about to lapse.

    Built for cron. A system action, not an operator one — there is no `--by`,
    because nobody is deciding anything here; the TTL already decided. If the
    chat transport is missing or broken the warning still lands in the audit
    log and on stdout, and the entry still lapses on schedule: the point of
    fail-closed expiry is that no delivery failure can extend authority.
    """
    within = _parse_window(args.within, "--within")
    now = datetime.now().astimezone()

    if args.dry_run:
        # Nothing sent, nothing recorded — so a later real run still warns.
        due = [e for e in store.expiring_within(within, now=now)
               if (e.action_class, e.expires_at or "") not in store.warned_expiries(audit)]
        print(f"DRY RUN — {len(due)} entr{'y' if len(due) == 1 else 'ies'} would be warned "
              f"about (within {args.within}):")
        for entry in due:
            print(f"  {entry.action_class:32} owner {entry.owner:16} expires "
                  f"{_expiry_phrase(entry, now)}")
        return 0

    notifier = None
    if settings.slack_bot_token and settings.slack_channel_id:
        from kronagent.chatops import ChatOpsNotifier

        def _send(entry: AllowlistEntry) -> bool:
            remaining = _humanize(parse_ts(entry.expires_at) - now)
            return ChatOpsNotifier.send_expiry_warning(settings, entry, remaining=remaining)

        notifier = _send

    warned = asyncio.run(store.warn_expiring(audit=audit, within=within, notify=notifier, now=now))
    if not warned:
        print(f"No allowlist entries expiring within {args.within} that haven't been warned about.")
        return 0

    print(f"Warned about {len(warned)} expiring entr{'y' if len(warned) == 1 else 'ies'}:")
    for entry, notified in warned:
        if notified:
            delivery = "notified via Slack"
        elif notifier is None:
            delivery = "NOT DELIVERED — no chat transport configured"
        else:
            delivery = "NOT DELIVERED — Slack send failed (see error above)"
        print(f"\n  {entry.action_class} — expires {_expiry_phrase(entry, now)}")
        print(f"      owner {entry.owner} — {delivery}")
        print(f"      promoted by {entry.promoted_by}: {entry.reason}")
        print(f"      last fired: {_fired_phrase(entry, now)}")
        print(f"      renew:  python3 promote.py add {entry.action_class} "
              f"--by <you> --reason \"<why it still applies>\" --expires-in 90d")
    print("\nDoing nothing is a valid answer: an unrenewed entry lapses on its own and the "
          "class goes back to requiring human approval.")
    return 0


def cmd_reassign(store: AllowlistStore, audit: AuditLog, settings: Settings,
                 actor: AuthContext, args: argparse.Namespace) -> int:
    ac = _parse_action_class(args.action_class)
    try:
        entry = asyncio.run(store.set_owner(ac, owner=args.to, by=actor.operator_id,
                                            reason=args.reason, audit=audit,
                                            actor_fields=actor.audit_fields(),
                                            owner_check=_owner_check(settings)))
    except OwnerNotInStandingError as exc:
        return _refuse_owner(exc)
    if entry is None:
        print(f"{ac.value} is not on the allowlist — nothing to reassign "
              f"(no-op, still recorded for the audit trail).")
        return 0
    print(f"{ac.value} is now owned by {entry.owner} (reassigned by {actor.label}).")
    print(f"  Promotion history unchanged: promoted by {entry.promoted_by} at "
          f"{entry.promoted_at}. Ownership moves; the decision it records doesn't.")
    return 0


def main() -> int:
    settings = Settings.from_env()
    store = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    audit = AuditLog(settings.audit_log_path)

    parser = argparse.ArgumentParser(description="Kronagent earn-trust governance CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show the current auto-execute allowlist")

    # Governance is the most consequential action in the system, so it requires
    # the PROMOTE permission (admin) in enforced mode. In unauthenticated mode
    # (no registry) it falls back to free-text --by, audited as unverified.
    def _add_identity(p: argparse.ArgumentParser) -> None:
        p.add_argument("--by", help="operator identity, unauthenticated mode (audited)")
        p.add_argument("--as", dest="as_operator", help="authenticated operator id (enforced mode)")
        p.add_argument("--token", help="operator token (or set KRONAGENT_OPERATOR_TOKEN)")

    p_add = sub.add_parser("add", help="promote an action class to autonomous execution")
    p_add.add_argument("action_class")
    _add_identity(p_add)
    p_add.add_argument("--reason", required=True, help="why this class has earned trust (audited)")
    p_add.add_argument("--expires-in", metavar="DURATION",
                       help="TTL for this promotion, e.g. 90d / 12h / 2w. After it elapses the "
                            "class routes back to human approval until renewed (audited). "
                            "Omit for standing authority.")
    p_add.add_argument("--owner", metavar="OPERATOR",
                       help="who is accountable for this entry and gets asked to renew it. "
                            "Defaults to the promoter; on a renewal, defaults to the existing "
                            "owner. Reassign later with `reassign`.")

    p_rm = sub.add_parser("remove", help="demote an action class back to requiring approval")
    p_rm.add_argument("action_class")
    _add_identity(p_rm)
    p_rm.add_argument("--reason", required=True, help="why this class is being demoted (audited)")

    p_warn = sub.add_parser(
        "warn-expiring", help="notify owners, once each, that their entry is about to lapse "
                              "(for cron; no --by, it's a system action)")
    p_warn.add_argument("--within", default=settings.allowlist_warn_within, metavar="DURATION",
                        help=f"how far ahead to look (default {settings.allowlist_warn_within}, "
                             f"from KRONAGENT_ALLOWLIST_WARN_WITHIN)")
    p_warn.add_argument("--dry-run", action="store_true",
                        help="show who would be warned without sending or recording anything")

    p_own = sub.add_parser(
        "reassign", help="hand an entry to a new owner (promotion history is left intact)")
    p_own.add_argument("action_class")
    p_own.add_argument("--to", required=True, metavar="OPERATOR",
                       help="the new accountable owner")
    _add_identity(p_own)
    p_own.add_argument("--reason", required=True,
                       help="why ownership is moving, e.g. 'dana moved to platform' (audited)")

    p_rev = sub.add_parser(
        "review", help="periodic re-earn-it review: every entry with its promotion reason, "
                       "who promoted it, and when it last fired")
    _add_identity(p_rev)
    p_rev.add_argument("--stale-after", default=f"{DEFAULT_STALE_AFTER_DAYS}d", metavar="DURATION",
                       help=f"flag entries that haven't fired in this long "
                            f"(default {DEFAULT_STALE_AFTER_DAYS}d)")
    p_rev.add_argument("--expiring-within", default="14d", metavar="DURATION",
                       help="flag entries whose TTL lapses within this window (default 14d)")
    p_rev.add_argument("--strict", action="store_true",
                       help="exit 3 if any entry needs a decision (for scheduled reviews)")

    args = parser.parse_args()

    # Sweep lapsed TTLs before every command so the audit chain records the
    # expiry, and so no command can display an expired entry as if it were
    # still granting autonomy. The gate does not depend on this — the store
    # refuses an expired entry whether or not the sweep has run.
    for lapsed in asyncio.run(store.expire_due(audit=audit)):
        print(f"EXPIRED: {lapsed.action_class} — TTL elapsed at {lapsed.expires_at}; it requires "
              f"human approval again until renewed (recorded in the audit log).", file=sys.stderr)
    for entry, drift in asyncio.run(store.suspend_reclassified(audit=audit)):
        print(f"SUSPENDED: {entry.action_class} — {drift}; it requires human approval until "
              f"renewed against its current classification (recorded in the audit log).",
              file=sys.stderr)
    for entry, vacancy in asyncio.run(store.suspend_vacant_owners(
            audit=audit, owner_check=_owner_check(settings))):
        print(f"SUSPENDED: {entry.action_class} — {vacancy.reason}; it requires human approval "
              f"until renewed with an owner in standing or reassigned (recorded in the audit "
              f"log).", file=sys.stderr)

    if args.command == "list":
        return cmd_list(store, settings)
    if args.command == "add":
        actor = _resolve(settings, audit, args, Permission.PROMOTE)
        return cmd_add(store, audit, settings, actor, args)
    if args.command == "remove":
        actor = _resolve(settings, audit, args, Permission.PROMOTE)
        return cmd_remove(store, audit, actor, args)
    if args.command == "warn-expiring":
        return cmd_warn_expiring(store, audit, settings, args)
    if args.command == "reassign":
        # PROMOTE, not VIEW: moving ownership moves who can renew the entry,
        # which is a governance change even though the entry itself is untouched.
        actor = _resolve(settings, audit, args, Permission.PROMOTE)
        return cmd_reassign(store, audit, settings, actor, args)
    if args.command == "review":
        # Reviewing is a read, so VIEW is enough — but it is an attributed one:
        # the point of the command is that someone looked, and the audit log
        # records who.
        actor = _resolve(settings, audit, args, Permission.VIEW)
        return cmd_review(store, audit, settings, actor, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
