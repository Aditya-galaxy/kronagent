"""
Unconfirmed autonomous actions: Kronagent acted, and nobody has said whether
it was right.

When a promoted action class runs unattended, a person finds out afterwards,
if at all. The promotion model depends on that afterwards happening: an
outcome recorded for the finding is what keeps the class's evidence honest, and
an unwarranted one is what suspends it (allowlist.suspend_unwarranted). An
autonomous action with no recorded outcome is the gap between those two. It
neither supports the promotion nor can end it.

This module finds that gap and makes it loud. It does not close it by itself.
In particular it never releases anything: containment that nobody has reviewed
stays in place. "Release after N minutes unless confirmed" would let a real
attacker back in whenever nobody was watching, which is the failure this
project's design refuses everywhere else. A review that fails open is not a
control; an expiry that fails closed is. So silence here costs noise, in
`outcome.py pending` (exit 3 when anything is overdue, for cron) and at the top
of the weekly digest, and never costs containment.

What counts as acting: the policy engine's disposition was auto_execute. With
live execution, only actions whose containment record says they ran. In
dry-run nothing ran, so by default nothing is pending; `include_dry_run` lists
what would have run, which is what a shadow-mode team labels to build evidence.

What counts as confirming: any conclusive outcome for the finding, malicious
or benign. An "inconclusive" outcome says someone looked and couldn't tell,
which is not a confirmation.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from pydantic import BaseModel, Field

from .allowlist import parse_ts
from .outcomes import AnalystOutcome
from .shadow import KronagentCall

DEFAULT_CONFIRM_WITHIN = "24h"


class UnconfirmedAction(BaseModel):
    finding_id: str
    acted_at: str = ""
    age_hours: Optional[float] = None       # None: the record has no readable time
    overdue: bool = False
    executed: bool = False                  # False: dry-run, it would have run
    action_classes: list[str] = Field(default_factory=list)
    severity: Optional[float] = None
    looked_at_inconclusive: bool = False


def unconfirmed_actions(calls: dict[str, KronagentCall], outcomes: Iterable[AnalystOutcome], *,
                        now: datetime, confirm_within: timedelta,
                        include_dry_run: bool = False) -> list[UnconfirmedAction]:
    """Findings Kronagent acted on unattended that have no conclusive outcome,
    oldest first. A record with no readable time sorts first and is overdue: an
    action nobody can date is not one to assume was recent."""
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    by_finding = {o.finding_id: o for o in outcomes}
    pending: list[UnconfirmedAction] = []
    for fid, call in calls.items():
        if not call.unattended_actions:
            continue
        ran = sorted(set(call.executed_unattended))
        if not ran and not include_dry_run:
            continue
        outcome = by_finding.get(fid)
        if outcome is not None and outcome.verdict != "inconclusive":
            continue
        acted = parse_ts(call.unattended_at or call.first_seen)
        age = None if acted is None else (now - acted).total_seconds() / 3600
        pending.append(UnconfirmedAction(
            finding_id=fid, acted_at=call.unattended_at or call.first_seen,
            age_hours=None if age is None else round(age, 1),
            overdue=age is None or age > confirm_within.total_seconds() / 3600,
            executed=bool(ran),
            action_classes=ran or sorted({cls for cls, _ in call.unattended_actions}),
            severity=call.severity, looked_at_inconclusive=outcome is not None))
    return sorted(pending, key=lambda u: (u.age_hours is not None, -(u.age_hours or 0.0), u.finding_id))


def render_text(pending: list[UnconfirmedAction], confirm_within: str) -> str:
    if not pending:
        return "No autonomous action is waiting for an outcome."
    overdue = [u for u in pending if u.overdue]
    lines = [f"Autonomous actions with no recorded outcome: {len(pending)} "
             f"({len(overdue)} waiting longer than {confirm_within})", ""]
    for u in pending:
        age = "time unknown" if u.age_hours is None else f"{u.age_hours:.1f}h ago"
        sev = "?" if u.severity is None else f"{u.severity:.1f}"
        lines.append(
            f"  {'OVERDUE ' if u.overdue else '        '}{u.finding_id}  severity {sev}  "
            f"{'ran' if u.executed else 'would have run (dry-run)'}: {', '.join(u.action_classes)}  {age}"
            + ("  (marked inconclusive; still needs a verdict)" if u.looked_at_inconclusive else ""))
    lines += ["", "  Nothing here has been released, and nothing will be. Record what the team decided:",
              "    python3 outcome.py record <finding_id> --verdict malicious|benign "
              "--action contained|no_action --by <you>"]
    return "\n".join(lines)
