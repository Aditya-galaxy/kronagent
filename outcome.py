#!/usr/bin/env python3
"""
Record what the team decided about a finding, and score shadow mode against it.

    python3 outcome.py record <finding_id> --verdict malicious|benign|inconclusive \\
                              --action contained|no_action [--note TEXT] \\
                              (--by NAME | --as OPERATOR_ID --token TOKEN)
    python3 outcome.py list
    python3 outcome.py report [--json]

`--tenant` selects a tenant's audit log and outcome store (default: default).

Recording requires APPROVE. The outcomes are the ground truth a published
benchmark is scored against, so writing one carries the same trust as
authorising containment, and every write — including each revision — is
audited with what it replaced.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

from kronagent.allowlist import AllowlistStore, parse_duration
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.correlation import stale_correlations
from kronagent.evidence import unwarranted_autonomy
from kronagent.identity import AuthContext, AuthorizationError, Permission, resolve_actor
from kronagent.orchestrator import get_tenant_path
from kronagent.outcomes import AnalystOutcome, OutcomeStore
from kronagent.schemas import AuditRecord
from kronagent.shadow import build_report, calls_from_audit, render_text
from kronagent.unconfirmed import render_text as render_pending, unconfirmed_actions


def _resolve(settings: Settings, audit: AuditLog, args: argparse.Namespace) -> AuthContext:
    try:
        return resolve_actor(
            registry_path=settings.operator_registry_path,
            required=Permission.APPROVE,
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
            finding_id=getattr(args, "finding_id", "_access"), stage="access_denied",
            payload={"command": "outcome.record", "required": Permission.APPROVE.value,
                     "operator_id": getattr(args, "as_operator", None) or getattr(args, "by", None),
                     "error": str(exc)},
        )))
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        raise SystemExit(4)


def cmd_record(settings: Settings, audit: AuditLog, store: OutcomeStore,
               args: argparse.Namespace) -> int:
    calls = calls_from_audit(audit.records())
    if args.finding_id not in calls and not args.allow_unseen:
        # A typo'd finding id would otherwise create an outcome nothing can ever
        # be scored against — and would do it silently.
        print(f"No triage record for finding {args.finding_id!r} in this tenant's audit "
              f"log. Check the id, or pass --allow-unseen to record it anyway (it will "
              f"be listed in the report, not scored).", file=sys.stderr)
        return 2

    actor = _resolve(settings, audit, args)
    stored, previous = store.record(AnalystOutcome(
        finding_id=args.finding_id, verdict=args.verdict, team_action=args.action,
        recorded_by=actor.label, note=args.note or "",
    ))
    asyncio.run(audit.record(AuditRecord(
        finding_id=args.finding_id, stage="analyst_outcome",
        payload={
            "verdict": stored.verdict, "team_action": stored.team_action,
            "recorded_by": stored.recorded_by, "revision": stored.revision,
            "note": stored.note,
            "previous": ({"verdict": previous.verdict, "team_action": previous.team_action,
                          "recorded_by": previous.recorded_by}
                         if previous else None),
        },
    )))
    change = (f" (revision {stored.revision}, was {previous.verdict}/{previous.team_action})"
              if previous else "")
    print(f"Recorded {stored.verdict}/{stored.team_action} for {stored.finding_id} "
          f"by {stored.recorded_by}{change}.")
    if stored.verdict == "benign":
        # A benign finding is withdrawn from correlation history. Say which
        # recorded correlations leaned on it, so nobody keeps reading them as
        # a campaign.
        for item in stale_correlations(audit.records(), [stored.finding_id]):
            left = (f"; still linked to {', '.join(item['still_standing'])}" if item["still_standing"]
                    else "; no link is left")
            print(f"STALE: the correlation recorded for {item['finding_id']} cited {stored.finding_id}{left}.")
    for entry, reason in suspend_unwarranted_autonomy(settings, audit, store, args.tenant):
        print(f"SUSPENDED: {entry.action_class} — it {reason}. It requires human approval again "
              f"until {entry.owner} or another operator renews it (recorded in the audit log).")
    return 0


def suspend_unwarranted_autonomy(settings: Settings, audit: AuditLog, store: OutcomeStore,
                                 tenant: str) -> list:
    """An outcome can show that a promoted action class acted, with nobody
    asked, on something the team judged unwarranted. That withdraws its
    autonomy at once, here, where the outcome is recorded."""
    allowlist = AllowlistStore(get_tenant_path(settings.allowlist_store_path, tenant))
    offences = unwarranted_autonomy(calls_from_audit(audit.records()), store.list(), allowlist.list())
    return asyncio.run(allowlist.suspend_unwarranted(offences, audit=audit))


def cmd_list(store: OutcomeStore) -> int:
    outcomes = sorted(store.list(), key=lambda o: o.recorded_at)
    if not outcomes:
        print("No outcomes recorded.")
    for o in outcomes:
        rev = f"  (rev {o.revision})" if o.revision > 1 else ""
        print(f"{o.finding_id}  {o.verdict}/{o.team_action}  by {o.recorded_by} "
              f"at {o.recorded_at}{rev}" + (f"  — {o.note}" if o.note else ""))
    return 0


def cmd_pending(settings: Settings, audit: AuditLog, store: OutcomeStore, args: argparse.Namespace) -> int:
    """Autonomous actions nobody has recorded an outcome for. Exit 3 when any
    is overdue, so a scheduled run can page someone."""
    window = args.older_than or settings.confirm_within
    try:
        within = parse_duration(window)
    except ValueError as exc:
        print(f"--older-than: {exc}", file=sys.stderr)
        return 2
    pending = unconfirmed_actions(calls_from_audit(audit.records()), store.list(),
                                  now=datetime.now(timezone.utc), confirm_within=within,
                                  include_dry_run=args.include_dry_run)
    if args.overdue_only:
        pending = [u for u in pending if u.overdue]
    print(json.dumps([u.model_dump() for u in pending], indent=2) if args.json
          else render_pending(pending, window))
    return 3 if any(u.overdue for u in pending) else 0


def cmd_stale(audit: AuditLog, store: OutcomeStore, args: argparse.Namespace) -> int:
    """Recorded correlations that cite a finding the team has since judged benign."""
    withdrawn = [o.finding_id for o in store.list() if o.verdict == "benign"]
    stale = stale_correlations(audit.records(), withdrawn)
    if args.json:
        print(json.dumps(stale, indent=2))
        return 0
    if not stale:
        print("No recorded correlation cites a finding judged benign.")
    for item in stale:
        left = (f"still linked to {', '.join(item['still_standing'])}" if item["still_standing"]
                else "no link is left")
        print(f"{item['finding_id']}  cited {', '.join(item['withdrawn'])} (judged benign); {left}"
              + (f"  — {item['summary']}" if item["summary"] else ""))
    return 0


def cmd_report(audit: AuditLog, store: OutcomeStore, args: argparse.Namespace) -> int:
    report = build_report(calls_from_audit(audit.records()), store.list())
    print(json.dumps(report.model_dump(), indent=2) if args.json else render_text(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    ap = argparse.ArgumentParser(description="Kronagent shadow-mode outcomes")
    ap.add_argument("--tenant", default="default")
    sub = ap.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="record what the team decided (requires APPROVE)")
    rec.add_argument("finding_id")
    rec.add_argument("--verdict", required=True, choices=["malicious", "benign", "inconclusive"])
    rec.add_argument("--action", required=True, choices=["contained", "no_action"])
    rec.add_argument("--note")
    rec.add_argument("--allow-unseen", action="store_true",
                     help="record an outcome for a finding absent from the audit log")
    rec.add_argument("--by", help="operator identity, unauthenticated mode (audited)")
    rec.add_argument("--as", dest="as_operator", help="authenticated operator id")
    rec.add_argument("--token", help="operator token (or KRONAGENT_OPERATOR_TOKEN)")

    sub.add_parser("list", help="list recorded outcomes")
    pend = sub.add_parser("pending", help="autonomous actions with no recorded outcome; exit 3 if any "
                                          "is overdue. Nothing is ever released for lack of one.")
    pend.add_argument("--older-than", metavar="DURATION",
                      help="what counts as overdue, e.g. 4h (default: KRONAGENT_CONFIRM_WITHIN, 24h)")
    pend.add_argument("--overdue-only", action="store_true")
    pend.add_argument("--include-dry-run", action="store_true",
                      help="also list actions that would have run in dry-run: the findings a "
                           "shadow-mode team labels to build promotion evidence")
    pend.add_argument("--json", action="store_true")
    st = sub.add_parser("stale-correlations",
                        help="recorded correlations that cite a finding since judged benign")
    st.add_argument("--json", action="store_true")
    rep = sub.add_parser("report", help="score Kronagent's decisions against the team's")
    rep.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    audit = AuditLog(get_tenant_path(settings.audit_log_path, args.tenant))
    store = OutcomeStore(get_tenant_path(settings.outcome_store_path, args.tenant))

    if args.command == "record":
        return cmd_record(settings, audit, store, args)
    if args.command == "list":
        return cmd_list(store)
    if args.command == "stale-correlations":
        return cmd_stale(audit, store, args)
    if args.command == "pending":
        return cmd_pending(settings, audit, store, args)
    return cmd_report(audit, store, args)


if __name__ == "__main__":
    raise SystemExit(main())
