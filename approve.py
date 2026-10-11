#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent operator CLI — the human end of the earn-trust loop.

An action the policy engine could not clear for autonomy waits in the approval
store. An operator reviews it here and either authorizes execution (with
attribution and a reason, both audited) or denies it.

    python3 approve.py list                       # pending actions
    python3 approve.py list --all                 # every request, any status
    python3 approve.py show <request_id>          # full detail + planned calls
    python3 approve.py approve <request_id> --by alice --reason "confirmed malicious"
    python3 approve.py deny    <request_id> --by alice --reason "false positive"

Approval executes the action through the same containment executor the
autonomous path uses, so it honors dry_run and the kill switch: in dry-run,
approval validates the flow without touching AWS; with the kill switch on,
execution is refused outright.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from kronagent.approvals import ApprovalStore, now_iso
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.containment import ContainmentExecutor
from kronagent.identity import AuthContext, AuthorizationError, Permission, resolve_actor
from kronagent.insights import insight_tags, tag_labels
from kronagent.provenance import review_banner
from kronagent.oversight import (
    HASTY_DECISION_SECONDS,
    MIN_DECISIONS_FOR_SIGNAL,
    compute_metrics,
)
from kronagent.providers import build_containment_adapters
from kronagent.release import containments_from_audit
from kronagent.schemas import AuditRecord, BlastRadius, PolicyDecision


def _resolve(settings: Settings, audit: AuditLog, args: argparse.Namespace,
             required: Permission) -> AuthContext:
    """Resolve + authorize the acting operator. On failure, audit the denied
    attempt (a security event) and raise SystemExit(4)."""
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
            finding_id=getattr(args, "request_id", "_access"), stage="access_denied",
            payload={"command": args.command, "required": required.value,
                     "operator_id": getattr(args, "as_operator", None) or getattr(args, "by", None),
                     "error": str(exc)},
        )))
        print(f"ACCESS DENIED: {exc}", file=sys.stderr)
        raise SystemExit(4)


def _fmt(r) -> str:
    # Tags first, on the same line as the action: a reviewer under incident
    # pressure reads the top two lines and forms a judgement, so the
    # decision-relevant part has to be up there rather than nine fields down.
    labels = tag_labels(r)
    tags = ("  " + "  ".join(f"[{t}]" for t in labels)) if labels else ""
    return (f"{r.request_id}  [{r.status}]  {r.action_class.value} on {r.target}{tags}\n"
            f"    finding {r.finding_id} ({r.finding_type}), severity {r.severity}\n"
            f"    reason: {r.policy_reason}\n"
            f"    reversible={r.reversible} blast={r.blast_radius}")


def cmd_list(store: ApprovalStore, args: argparse.Namespace) -> int:
    items = store.list(status=None if args.all else "pending")
    if not items:
        print("No pending approval requests." if not args.all else "No approval requests.")
        return 0
    for r in items:
        print(_fmt(r))
        print()
    return 0


def cmd_show(store: ApprovalStore, args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    print(_fmt(r))
    tags = insight_tags(r)
    if tags:
        print()
        for t in tags:
            print(f"    [{t.label}] ({t.kind}) {t.why}")
        print()
    # Everything above this point Kronagent computed or copied from the finding.
    # Everything in this section a language model wrote after reading the
    # finding, which contains attacker-chosen text. It is printed separately,
    # under a header saying so, because side by side with policy_reason there
    # was no way to tell the two apart.
    banner = review_banner(r)
    if banner:
        print("    -- written by a language model: context, not evidence --")
        print(f"    {banner}")
        if r.threat_intel_summary:
            print(f"    threat intel: {r.threat_intel_summary}")
        if r.mitre_techniques:
            print(f"    MITRE ATT&CK (model-mapped): {', '.join(r.mitre_techniques)}")
        if r.correlation_summary:
            print(f"    correlation: {r.correlation_summary}")
        if r.incident_narrative:
            print(f"    narrative: {r.incident_narrative}")
        if r.incident_priority:
            print(f"    model-assigned priority: {r.incident_priority}"
                  f"{' (flagged to escalate)' if r.escalated else ''}")
        print("    -- end of model-written context --")
    print("    planned API calls:")
    for c in r.planned_api_calls:
        print(f"      $ {c}")
    print(f"    rollback: {r.rollback_hint}")
    if r.decided_by:
        print(f"    decided by {r.decided_by} at {r.decided_at}: {r.decision_reason}")
    if r.execution_detail:
        print(f"    execution: {r.execution_detail}")
    return 0


def cmd_stats(store: ApprovalStore, args: argparse.Namespace) -> int:
    """Is the approval queue still a control, or has it become a formality?"""
    m = compute_metrics(store.list(status=None))

    print(f"Approval oversight — {m.decided} decided, {m.pending} pending\n")
    print(f"  deny rate            {m.deny_rate:.1%}  ({m.denied} denied / {m.decided} decided)")
    if m.median_seconds_to_decide is not None:
        print(f"  time to decide       median {m.median_seconds_to_decide:.0f}s, "
              f"p90 {m.p90_seconds_to_decide:.0f}s")
    if m.consequential_decided:
        print(f"  destructive/irreversible decided   {m.consequential_decided}")
        print(f"    of those, decided in <{HASTY_DECISION_SECONDS:.0f}s  "
              f"{m.hasty_consequential} ({m.hasty_rate:.0%})")

    if m.by_operator:
        print("\n  by operator:")
        for st in m.by_operator:
            print(f"    {st.operator_id:20} {st.decided:4} decided  "
                  f"{st.denied:3} denied ({st.deny_rate:.0%})  {st.hasty:3} hasty")

    if m.warnings:
        print("\n  ⚠ THE CONTROL MAY BE DEGRADING:")
        for w in m.warnings:
            print(f"    - {w}")
        # Non-zero so this can run from cron and page someone.
        return 1

    if m.decided < MIN_DECISIONS_FOR_SIGNAL:
        print(f"\n  (fewer than {MIN_DECISIONS_FOR_SIGNAL} decisions — no rate here "
              f"means anything yet)")
    else:
        print("\n  No degradation signals.")
    return 0


def cmd_deny(store: ApprovalStore, audit: AuditLog, actor: AuthContext,
             args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    if r.status != "pending":
        print(f"Request {r.request_id} is '{r.status}', not pending — cannot deny.", file=sys.stderr)
        return 2
    r.status = "denied"
    r.decided_by = actor.operator_id
    r.decided_at = now_iso()
    r.decision_reason = args.reason
    store.update(r)
    asyncio.run(audit.record(AuditRecord(
        finding_id=r.finding_id, stage="approval",
        payload={"request_id": r.request_id, "decision": "denied",
                 "reason": args.reason,
                 "action_class": r.action_class.value, "target": r.target,
                 **actor.audit_fields()},
    )))
    print(f"Denied {r.request_id} ({r.action_class.value} on {r.target}) by {actor.label} — recorded.")
    return 0


def cmd_approve(store: ApprovalStore, audit: AuditLog, settings: Settings,
                actor: AuthContext, args: argparse.Namespace) -> int:
    r = store.get(args.request_id)
    if r is None:
        print(f"No such request: {args.request_id}", file=sys.stderr)
        return 2
    if r.status != "pending":
        print(f"Request {r.request_id} is '{r.status}', not pending — cannot approve.", file=sys.stderr)
        return 2

    if settings.kill_switch:
        print("KILL SWITCH ENGAGED — execution refused. Disengage KRONAGENT_KILL_SWITCH to proceed.",
              file=sys.stderr)
        return 3

    # Human authorization is the grant: synthesize an auto_execute decision.
    decision = PolicyDecision(
        action_class=r.action_class,
        disposition="auto_execute",
        reason=f"human-approved by {actor.operator_id}: {args.reason}",
        reversible=r.reversible,
        blast_radius=BlastRadius(r.blast_radius),
    )
    action = r.to_proposed_action()
    containment = ContainmentExecutor(settings, build_containment_adapters(settings))

    # Record the approval decision BEFORE execution, then the outcome after.
    async def _run():
        await audit.record(AuditRecord(
            finding_id=r.finding_id, stage="approval",
            payload={"request_id": r.request_id, "decision": "approved",
                     "reason": args.reason,
                     "action_class": r.action_class.value, "target": r.target,
                     **actor.audit_fields()},
        ))
        outcome = await containment.execute(action, decision)
        await audit.record(AuditRecord(
            finding_id=r.finding_id, stage="containment",
            payload={"request_id": r.request_id, **outcome.model_dump()},
        ))
        return outcome

    outcome = asyncio.run(_run())

    r.decided_by = actor.operator_id
    r.decided_at = now_iso()
    r.decision_reason = args.reason
    r.execution_detail = outcome.detail
    if outcome.executed:
        r.status = "executed"
    elif outcome.error:
        r.status = "failed"
    else:
        # dry-run: authorized but not actually executed
        r.status = "approved"
    store.update(r)

    print(f"Approved {r.request_id} by {actor.label}.")
    print(f"  {outcome.detail}")
    print(f"  rollback: {outcome.rollback_hint}")
    if r.status == "approved":
        print("  (DRY-RUN active — action authorized but not executed. "
              "Set KRONAGENT_DRY_RUN=false to execute for real.)")
    return 0


def cmd_executed(audit: AuditLog, settings: Settings, args: argparse.Namespace) -> int:
    """What Kronagent has contained and not yet released: what `release` can undo."""
    found = containments_from_audit(audit.records(), include_dry_run=settings.dry_run)
    if not args.all:
        found = [c for c in found if c.released_at is None]
    if not found:
        print("Nothing contained" + ("." if args.all else " that hasn't been released."))
        return 0
    for c in found:
        how = f"approved ({c.approved_request})" if c.approved_request else "unattended"
        state = (f"released {c.released_at} by {c.released_by}" if c.released_at
                 else ("in place" if c.executed else "dry-run: would be in place"))
        print(f"{c.finding_id}  {c.action.action_class.value}  {c.action.target}  [{c.action.provider}]  "
              f"{how}  {c.at}  — {state}")
    return 0


def cmd_release(audit: AuditLog, settings: Settings, actor: AuthContext, args: argparse.Namespace) -> int:
    """Undo one containment action Kronagent took. The target comes from the
    audit record of what was done, not from this command line."""
    live = [c for c in containments_from_audit(audit.records(), include_dry_run=settings.dry_run)
            if c.released_at is None and c.finding_id == args.finding_id
            and c.action.action_class.value == args.action_class
            and (args.target is None or c.action.target == args.target)]
    # The same action on the same target can have run more than once (a
    # redelivered finding); one release undoes it, so collapse them.
    by_target = {c.action.target: c for c in live}
    if not by_target:
        print(f"Nothing to release: Kronagent has no {args.action_class} in place for finding "
              f"{args.finding_id}" + (f" on {args.target}" if args.target else "")
              + ". See `approve.py executed`.", file=sys.stderr)
        return 2
    if len(by_target) > 1:
        print(f"{args.action_class} is in place on several targets for {args.finding_id}: "
              f"{', '.join(sorted(by_target))}. Name one with --target.", file=sys.stderr)
        return 2
    if settings.kill_switch:
        print("KILL SWITCH ENGAGED — Kronagent changes nothing while it is on, a release included. "
              "Disengage KRONAGENT_KILL_SWITCH to proceed.", file=sys.stderr)
        return 3
    (containment,) = by_target.values()
    action = containment.action
    executor = ContainmentExecutor(settings, build_containment_adapters(settings))

    # The decision is recorded before anything is changed, the result after.
    async def _run():
        await audit.record(AuditRecord(
            finding_id=containment.finding_id, stage="release_request",
            payload={"action_class": action.action_class.value, "target": action.target,
                     "provider": action.provider, "reason": args.reason,
                     "contained_at": containment.at,
                     "contained_by": containment.approved_request or "policy (unattended)",
                     **actor.audit_fields()},
        ))
        outcome = await executor.release(action)
        await audit.record(AuditRecord(
            finding_id=containment.finding_id, stage="release",
            payload={**outcome.model_dump(), "provider": action.provider, "reason": args.reason,
                     **actor.audit_fields()},
        ))
        return outcome

    outcome = asyncio.run(_run())
    print(f"Release of {action.action_class.value} on {action.target} requested by {actor.label}.")
    print(f"  {outcome.detail}")
    for call in outcome.api_calls:
        print(f"    {call}")
    if outcome.released:
        print("  If this containment was a mistake, record it, so the action class's evidence shows it:")
        print(f"    python3 outcome.py record {containment.finding_id} --verdict benign --action no_action "
              f"--by <you>")
        return 0
    if outcome.dry_run and outcome.supported:
        print("  (DRY-RUN active — nothing was changed. Set KRONAGENT_DRY_RUN=false to release for real.)")
        return 0
    return 1 if outcome.error else (5 if not outcome.supported else 0)


def main() -> int:
    settings = Settings.from_env()
    store = ApprovalStore(settings.approval_store_path)
    audit = AuditLog(settings.audit_log_path)

    parser = argparse.ArgumentParser(description="Kronagent approval CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list pending (or all) approval requests")
    p_list.add_argument("--all", action="store_true", help="show requests of every status")

    p_show = sub.add_parser("show", help="show one request in full")
    p_show.add_argument("request_id")

    sub.add_parser(
        "stats",
        help="oversight health: deny rate, time-to-decide, hasty approvals "
             "(exits 1 if the control looks degraded)",
    )

    # Identity flags shared by the mutating commands. In unauthenticated mode
    # (no registry) pass --by. In enforced mode (registry configured) pass
    # --as <operator_id> and a token (--token or KRONAGENT_OPERATOR_TOKEN).
    def _add_identity(p: argparse.ArgumentParser) -> None:
        p.add_argument("--by", help="operator identity, unauthenticated mode (audited)")
        p.add_argument("--as", dest="as_operator", help="authenticated operator id (enforced mode)")
        p.add_argument("--token", help="operator token (or set KRONAGENT_OPERATOR_TOKEN)")
        p.add_argument("--reason", required=True, help="justification (audited)")

    p_appr = sub.add_parser("approve", help="authorize and execute an action")
    p_appr.add_argument("request_id")
    _add_identity(p_appr)

    p_deny = sub.add_parser("deny", help="reject an action")
    p_deny.add_argument("request_id")
    _add_identity(p_deny)

    p_exec = sub.add_parser("executed", help="containment actions in place: what `release` can undo")
    p_exec.add_argument("--all", action="store_true", help="include ones already released")

    p_rel = sub.add_parser(
        "release", help="undo a containment action Kronagent took (a person's decision; nothing "
                        "is ever released automatically)")
    p_rel.add_argument("finding_id")
    p_rel.add_argument("action_class")
    p_rel.add_argument("--target", help="which target, when the action is in place on several")
    _add_identity(p_rel)

    args = parser.parse_args()
    if args.command == "list":
        return cmd_list(store, args)
    if args.command == "executed":
        return cmd_executed(audit, settings, args)
    if args.command == "release":
        # APPROVE: taking containment away is as consequential as authorising it.
        actor = _resolve(settings, audit, args, Permission.APPROVE)
        return cmd_release(audit, settings, actor, args)
    if args.command == "show":
        return cmd_show(store, args)
    if args.command == "stats":
        return cmd_stats(store, args)
    if args.command == "approve":
        actor = _resolve(settings, audit, args, Permission.APPROVE)
        return cmd_approve(store, audit, settings, actor, args)
    if args.command == "deny":
        actor = _resolve(settings, audit, args, Permission.APPROVE)
        return cmd_deny(store, audit, actor, args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
