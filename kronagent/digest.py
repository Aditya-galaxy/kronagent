"""
The weekly digest: what shadow mode saw, decided and got wrong, for one tenant.

The roadmap asks for a weekly incident digest for design partners. The version
worth sending is not a highlights reel. A partner running Kronagent in shadow
mode needs four things from it, in this order:

  1. Anything that means the rest cannot be trusted — a broken audit chain, a
     containment that actually executed, an approval queue that has stopped
     being a control, or a week with no findings at all (which is how every
     ingestion wiring fault presents: silence, indistinguishable from a quiet
     account).
  2. What arrived and what Kronagent decided about it, including what triage
     dismissed.
  3. What it would have done — every planned containment, by action class.
  4. How that compared with what the team actually did, with every
     disagreement listed.

It deliberately contains no model-written text. Threat-intel summaries,
correlation prose and triage justifications are written by a model that read
attacker-influenced telemetry; a digest emailed to a customer is the last place
that text should appear unmarked. Counts, verdicts, action classes, severities
and the analysts' own notes only — asserted in tests/test_digest.py.

Nothing here sends anything. It renders; delivery is the operator's choice.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from pydantic import BaseModel, Field

from .model import severity_band
from .allowlist import parse_duration
from .outcomes import AnalystOutcome
from .oversight import compute_metrics
from .shadow import ShadowReport, build_report, calls_from_audit, render_text
from .unconfirmed import DEFAULT_CONFIRM_WITHIN, UnconfirmedAction, unconfirmed_actions

#: Audit stages that mean a safety mechanism fired or something went wrong.
SAFETY_STAGES = ("trajectory_halt", "trajectory_scope_violation", "security_alert",
                 "access_denied", "error")


def parse_ts(value: Any) -> Optional[datetime]:
    """An ISO-8601 timestamp as an aware UTC datetime, or None if unreadable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class Digest(BaseModel):
    tenant_id: str
    window_start: str
    window_end: str
    days: int
    dry_run: bool

    chain_ok: bool
    chain_broken_at: Optional[int] = None
    unreadable_timestamps: int = 0

    findings: int = 0
    by_severity_band: dict[str, int] = Field(default_factory=dict)
    model_actionable: int = 0
    model_dismissed: int = 0
    rescued_by_floor: int = 0

    would_contain: int = 0
    would_auto_execute: int = 0
    planned_by_action_class: dict[str, int] = Field(default_factory=dict)
    executed_containments: int = 0

    approvals_created: int = 0
    approvals_decided: int = 0
    approvals_pending: int = 0
    oldest_pending_hours: Optional[float] = None
    oversight_warnings: list[str] = Field(default_factory=list)

    safety_events: dict[str, int] = Field(default_factory=dict)

    shadow: ShadowReport = Field(default_factory=ShadowReport)
    # Autonomous actions that really ran and still have no recorded outcome.
    # All-time, not windowed: the one from three weeks ago is the worst one.
    unconfirmed: list[UnconfirmedAction] = Field(default_factory=list)
    confirm_within: str = DEFAULT_CONFIRM_WITHIN
    alerts: list[str] = Field(default_factory=list)


def build_digest(
    tenant_id: str,
    records: Iterable[dict],
    approvals: Iterable[Any],
    outcomes: Iterable[AnalystOutcome],
    *,
    now: datetime,
    days: int = 7,
    dry_run: bool = True,
    chain: tuple[bool, Optional[int]] = (True, None),
    confirm_within: str = DEFAULT_CONFIRM_WITHIN,
) -> Digest:
    if days <= 0:
        raise ValueError(f"days must be positive, got {days}")
    end = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    start = end - timedelta(days=days)

    records = list(records)
    outcomes = list(outcomes)
    unreadable = 0
    windowed: list[dict] = []
    for rec in records:
        ts = parse_ts(rec.get("ts"))
        if ts is None:
            unreadable += 1
            continue
        if start <= ts <= end:
            windowed.append(rec)

    calls = calls_from_audit(windowed)
    approvals = list(approvals)

    d = Digest(
        tenant_id=tenant_id, window_start=start.isoformat(), window_end=end.isoformat(),
        days=days, dry_run=dry_run, chain_ok=chain[0], chain_broken_at=chain[1],
        unreadable_timestamps=unreadable, findings=len(calls),
    )

    bands: Counter[str] = Counter()
    planned: Counter[str] = Counter()
    for call in calls.values():
        bands[severity_band(call.severity) if call.severity is not None else "unknown"] += 1
        d.model_actionable += call.model_actionable
        d.model_dismissed += not call.model_actionable
        d.rescued_by_floor += call.rescued_by_floor
        d.would_contain += call.would_contain
        d.would_auto_execute += call.would_auto_execute
        planned.update(call.planned_action_classes)
    d.by_severity_band = dict(sorted(bands.items()))
    d.planned_by_action_class = dict(planned.most_common())

    d.executed_containments = sum(
        1 for r in windowed
        if r.get("stage") == "containment" and (r.get("payload") or {}).get("executed") is True)
    d.safety_events = {
        stage: n for stage, n in Counter(
            r.get("stage") for r in windowed if r.get("stage") in SAFETY_STAGES).items()}

    pending_ages: list[float] = []
    for a in approvals:
        created, decided = parse_ts(getattr(a, "created_at", None)), parse_ts(getattr(a, "decided_at", None))
        if created and start <= created <= end:
            d.approvals_created += 1
        if decided and start <= decided <= end:
            d.approvals_decided += 1
        if getattr(a, "status", None) == "pending":
            d.approvals_pending += 1
            if created:
                pending_ages.append((end - created).total_seconds() / 3600)
    d.oldest_pending_hours = round(max(pending_ages), 1) if pending_ages else None
    # All-time, not windowed: rubber-stamping is a property of the process, and a
    # quiet week does not make a degraded queue healthy.
    d.oversight_warnings = compute_metrics(approvals).warnings

    # Only outcomes for findings in this window are scored here. Passing every
    # outcome would list older findings as "outcomes Kronagent never saw", which
    # is false — it saw them, just not this week.
    d.shadow = build_report(calls, [o for o in outcomes if o.finding_id in calls])

    d.confirm_within = confirm_within
    d.unconfirmed = unconfirmed_actions(calls_from_audit(records), outcomes, now=end,
                                        confirm_within=parse_duration(confirm_within))

    d.alerts = _alerts(d)
    return d


def _alerts(d: Digest) -> list[str]:
    """Most severe first. Each one is a reason not to trust what follows."""
    out: list[str] = []
    if not d.chain_ok:
        out.append(f"AUDIT CHAIN BROKEN at line {d.chain_broken_at}. The records this digest "
                   f"is built from may have been altered; investigate before relying on it.")
    if d.executed_containments:
        mode = ("DRY-RUN is set, so this should not happen — confirm the setting and when "
                "it changed" if d.dry_run else "live execution is enabled")
        out.append(f"{d.executed_containments} containment action(s) actually EXECUTED in this "
                   f"window; {mode}.")
    overdue = [u for u in d.unconfirmed if u.overdue]
    if overdue:
        ages = [u.age_hours for u in overdue if u.age_hours is not None]
        oldest = f"the oldest for {max(ages):.0f}h" if ages else "at a time the record doesn't give"
        out.append(f"{len(overdue)} autonomous action(s) have had no recorded outcome for more than "
                   f"{d.confirm_within}, {oldest}. Nobody has said whether Kronagent was right. Nothing "
                   f"has been released. Run `outcome.py pending`.")
    if d.findings == 0:
        out.append("No findings were processed in this window. If a connection is healthy, "
                   "this is how an ingestion wiring fault presents — check the boot log and "
                   "the [INGEST] lines before concluding the account was quiet.")
    if d.oversight_warnings:
        out.append(f"The approval queue shows {len(d.oversight_warnings)} sign(s) of becoming a "
                   f"formality — see Oversight below.")
    if d.safety_events:
        out.append("Safety mechanisms fired: "
                   + ", ".join(f"{k} ×{v}" for k, v in sorted(d.safety_events.items())) + ".")
    if d.unreadable_timestamps:
        out.append(f"{d.unreadable_timestamps} audit record(s) had unreadable timestamps and "
                   f"could not be placed in any window.")
    return out


def render_markdown(d: Digest) -> str:
    lines = [
        f"# Kronagent weekly digest — tenant `{d.tenant_id}`",
        f"{d.window_start[:10]} → {d.window_end[:10]} ({d.days} days) · "
        f"{'DRY-RUN (shadow mode)' if d.dry_run else 'LIVE EXECUTION'} · "
        f"audit chain {'verified' if d.chain_ok else 'BROKEN'}",
        "",
    ]
    if d.alerts:
        lines += ["## Needs attention", ""] + [f"- **{a}**" for a in d.alerts] + [""]

    bands = ", ".join(f"{k} {v}" for k, v in d.by_severity_band.items()) or "none"
    lines += [
        "## What arrived",
        f"- {d.findings} finding(s): {bands}",
        f"- triage: {d.model_actionable} actionable, {d.model_dismissed} dismissed"
        f"{f' ({d.rescued_by_floor} dismissed but sent to a human by the severity floor)' if d.rescued_by_floor else ''}",
        "",
        "## What Kronagent would have done",
        f"- {d.would_contain} finding(s) with containment planned; "
        f"{d.would_auto_execute} eligible to run without a human",
    ]
    lines += [f"  - `{ac}` ×{n}" for ac, n in d.planned_by_action_class.items()]
    lines += [f"- executed: {d.executed_containments}", ""]

    oldest = f"; oldest waiting {d.oldest_pending_hours}h" if d.oldest_pending_hours is not None else ""
    lines += [
        "## Oversight",
        f"- approvals: {d.approvals_created} created, {d.approvals_decided} decided this window; "
        f"{d.approvals_pending} pending{oldest}",
    ]
    lines += [f"- ⚠ {w}" for w in d.oversight_warnings] or ["- no degradation signals (all-time)"]
    if d.unconfirmed:
        lines.append(f"- autonomous actions awaiting an outcome (all-time): {len(d.unconfirmed)}")
        lines += [f"  - `{u.finding_id}` {', '.join(u.action_classes)}, "
                  f"{'time unknown' if u.age_hours is None else f'{u.age_hours:.0f}h ago'}"
                  f"{' — OVERDUE' if u.overdue else ''}" for u in d.unconfirmed]
    else:
        lines.append("- autonomous actions awaiting an outcome: none")
    lines += ["", "## Against the team", "```", render_text(d.shadow), "```", ""]
    lines.append("_No model-written text is included in this digest. Notes under "
                 "disagreements are the analysts' own._")
    return "\n".join(lines)
