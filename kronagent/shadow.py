"""
Shadow mode: what Kronagent would have done, against what the team did.

The roadmap is blunt about why this matters. Shadow mode is the only honest way
to earn the right to execute, and it produces the strongest thing Kronagent can
show anyone: a number, from the customer's own environment, that Kronagent did
not choose. The offline evaluation gate cannot be that number — it runs over
synthetic cases, and its triage F1 is ~100% by construction.

This module builds the number without inflating it. Kronagent's side comes from
the audit log, which already records a triage verdict for *every* finding —
including the ones triage dismissed, which never reach an approval queue and so
would be invisible to any comparison built from approvals alone. The team's side
comes from `outcomes.py`.

What it refuses to do, each asserted in tests/test_shadow.py:

  - count a finding with no recorded outcome as agreement;
  - score an "inconclusive" outcome either way;
  - credit the triage model for an attack the severity floor rescued from its
    dismissal — that is a model miss the safeguard caught, and reported as one;
  - truncate the list of disagreements. The report is only worth publishing with
    its losses, so it always carries every one.

Nothing here changes a decision. It reads records already written.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Iterable, Optional

from pydantic import BaseModel, Field

from .outcomes import AnalystOutcome
from .stats import wilson_score_interval

# Below this many scored findings, the report still computes every rate and
# interval but says plainly that the result is not ready to publish. It is a
# prompt, not a statistical law — the interval is the real statement of
# uncertainty, and at n=30 a 90% agreement rate still has a lower bound near 74%.
MIN_SCORED_FOR_PUBLICATION = 30

_WOULD_CONTAIN = {"auto_execute", "requires_approval"}

# Disagreement kinds. Named so a reader can act on each without decoding flags.
MISSED_ATTACK = "missed_attack"
RESCUED_BY_FLOOR = "missed_by_model_rescued_by_severity_floor"
FALSE_ALARM = "false_alarm"
WOULD_CONTAIN_TEAM_DID_NOT = "would_have_contained_team_did_not"
TEAM_CONTAINED_KRONAGENT_WOULD_NOT = "team_contained_kronagent_would_not"


class KronagentCall(BaseModel):
    """What Kronagent decided about one finding, reconstructed from the audit log."""

    finding_id: str
    first_seen: str = ""
    severity: Optional[float] = None
    model_actionable: bool
    # The triage model dismissed it, and the severity floor sent it to a human.
    rescued_by_floor: bool = False
    would_contain: bool = False
    would_auto_execute: bool = False
    planned_action_classes: list[str] = Field(default_factory=list)
    # The same plans with the provider each would run on, for evidence scoped
    # the way a promotion is scoped: (action_class, provider).
    planned_actions: list[tuple[str, str]] = Field(default_factory=list)
    # The subset the policy engine let run with nobody asked: (action_class,
    # provider) for every auto_execute disposition.
    unattended_actions: list[tuple[str, str]] = Field(default_factory=list)


def calls_from_audit(records: Iterable[dict]) -> dict[str, KronagentCall]:
    """One KronagentCall per finding, from audit records in chain order.

    Delivery is at-least-once, so a finding can be processed more than once. A
    new triage record starts that finding's call afresh: the latest complete
    processing is what Kronagent decided, and policy records from an earlier
    attempt must not leak into it.

    Findings with no triage record — a pipeline error before triage, say — are
    omitted. Kronagent made no call on them, and inventing one would be scoring
    something that did not happen.
    """
    calls: dict[str, KronagentCall] = {}
    for rec in records:
        stage, fid = rec.get("stage"), rec.get("finding_id")
        payload = rec.get("payload") or {}
        if not fid:
            continue
        if stage == "triage":
            calls[fid] = KronagentCall(
                finding_id=fid,
                first_seen=rec.get("ts", ""),
                severity=payload.get("severity"),
                model_actionable=bool(payload.get("is_actionable_threat")),
            )
        elif fid not in calls:
            continue
        elif stage == "triage_override":
            calls[fid].rescued_by_floor = True
        elif stage == "policy":
            decision = payload.get("decision") or {}
            action = payload.get("action") or {}
            disposition = decision.get("disposition")
            if disposition in _WOULD_CONTAIN:
                calls[fid].would_contain = True
                if action.get("action_class"):
                    calls[fid].planned_action_classes.append(str(action["action_class"]))
                    calls[fid].planned_actions.append(
                        (str(action["action_class"]), str(action.get("provider") or "")))
            if disposition == "auto_execute":
                calls[fid].would_auto_execute = True
                if action.get("action_class"):
                    calls[fid].unattended_actions.append(
                        (str(action["action_class"]), str(action.get("provider") or "")))
    return calls


class AgreementStats(BaseModel):
    agree: int = 0
    scored: int = 0
    rate: Optional[float] = None
    ci_low: Optional[float] = None
    ci_high: Optional[float] = None

    @classmethod
    def of(cls, agree: int, scored: int) -> "AgreementStats":
        if scored == 0:
            return cls()
        low, high = wilson_score_interval(agree, scored)
        return cls(agree=agree, scored=scored, rate=agree / scored, ci_low=low, ci_high=high)


class TriageStats(AgreementStats):
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None


class Disagreement(BaseModel):
    finding_id: str
    kinds: list[str]
    severity: Optional[float] = None
    model_actionable: bool
    rescued_by_floor: bool
    would_contain: bool
    planned_action_classes: list[str] = Field(default_factory=list)
    analyst_verdict: str
    team_action: str
    recorded_by: str
    note: str = ""


class ShadowReport(BaseModel):
    findings_seen: int = 0
    scored: int = 0
    inconclusive: int = 0
    unlabeled: int = 0
    # Outcomes recorded for findings this tenant's audit log never saw. Listed
    # rather than scored: there is no Kronagent decision to compare them with.
    outcomes_without_a_kronagent_call: list[str] = Field(default_factory=list)
    revised_outcomes: int = 0
    rescued_by_floor: int = 0
    triage: TriageStats = Field(default_factory=TriageStats)
    containment: AgreementStats = Field(default_factory=AgreementStats)
    disagreements: list[Disagreement] = Field(default_factory=list)
    publishable: bool = False
    notes: list[str] = Field(default_factory=list)


def build_report(calls: dict[str, KronagentCall],
                 outcomes: Iterable[AnalystOutcome]) -> ShadowReport:
    by_finding = {o.finding_id: o for o in outcomes}
    report = ShadowReport(findings_seen=len(calls))
    report.outcomes_without_a_kronagent_call = sorted(set(by_finding) - set(calls))
    report.revised_outcomes = sum(1 for o in by_finding.values() if o.revision > 1)

    tp = fp = fn = tn = 0
    contain_agree = 0

    for fid in sorted(calls, key=lambda f: (calls[f].first_seen, f)):
        call = calls[fid]
        outcome = by_finding.get(fid)
        if outcome is None:
            report.unlabeled += 1
            continue
        if outcome.verdict == "inconclusive":
            report.inconclusive += 1
            continue

        report.scored += 1
        malicious = outcome.verdict == "malicious"
        kinds: list[str] = []

        # Triage is scored on the MODEL's verdict. A floor rescue is not credited
        # to the model: it missed, and the safeguard caught it.
        if call.model_actionable and malicious:
            tp += 1
        elif call.model_actionable and not malicious:
            fp += 1
            kinds.append(FALSE_ALARM)
        elif not call.model_actionable and malicious:
            fn += 1
            if call.rescued_by_floor:
                report.rescued_by_floor += 1
                kinds.append(RESCUED_BY_FLOOR)
            else:
                kinds.append(MISSED_ATTACK)
        else:
            tn += 1

        team_contained = outcome.team_action == "contained"
        if call.would_contain == team_contained:
            contain_agree += 1
        elif call.would_contain:
            kinds.append(WOULD_CONTAIN_TEAM_DID_NOT)
        else:
            kinds.append(TEAM_CONTAINED_KRONAGENT_WOULD_NOT)

        if kinds:
            report.disagreements.append(Disagreement(
                finding_id=fid, kinds=kinds, severity=call.severity,
                model_actionable=call.model_actionable,
                rescued_by_floor=call.rescued_by_floor,
                would_contain=call.would_contain,
                planned_action_classes=call.planned_action_classes,
                analyst_verdict=outcome.verdict, team_action=outcome.team_action,
                recorded_by=outcome.recorded_by, note=outcome.note,
            ))

    base = AgreementStats.of(tp + tn, report.scored)
    report.triage = TriageStats(
        **base.model_dump(),
        true_positive=tp, false_positive=fp, false_negative=fn, true_negative=tn,
        precision=(tp / (tp + fp)) if (tp + fp) else None,
        recall=(tp / (tp + fn)) if (tp + fn) else None,
    )
    report.containment = AgreementStats.of(contain_agree, report.scored)
    report.publishable = report.scored >= MIN_SCORED_FOR_PUBLICATION

    if not report.publishable:
        report.notes.append(
            f"{report.scored} scored finding(s); fewer than {MIN_SCORED_FOR_PUBLICATION} is "
            f"not ready to publish. The rates and intervals below are still correct — "
            f"the intervals are simply wide.")
    if report.unlabeled:
        report.notes.append(
            f"{report.unlabeled} finding(s) have no recorded outcome and are excluded, "
            f"not counted as agreement.")
    if report.revised_outcomes:
        report.notes.append(
            f"{report.revised_outcomes} outcome(s) were revised after first being recorded.")
    return report


def _pct(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def render_text(report: ShadowReport) -> str:
    """Human-readable report. Every disagreement is printed — no truncation."""
    t, c = report.triage, report.containment
    lines = [
        "Shadow mode — Kronagent's decisions against the team's",
        "",
        f"  findings seen      {report.findings_seen}",
        f"  scored             {report.scored}",
        f"  inconclusive       {report.inconclusive}   (recorded, not scored)",
        f"  unlabeled          {report.unlabeled}   (no outcome recorded, not scored)",
        "",
        f"  triage agreement       {_pct(t.rate)}  "
        f"(95% CI {_pct(t.ci_low)}–{_pct(t.ci_high)}, {t.agree}/{t.scored})",
        f"    precision {_pct(t.precision)}   recall {_pct(t.recall)}   "
        f"TP {t.true_positive}  FP {t.false_positive}  FN {t.false_negative}  TN {t.true_negative}",
        f"    model misses caught by the severity floor: {report.rescued_by_floor}",
        f"  containment agreement  {_pct(c.rate)}  "
        f"(95% CI {_pct(c.ci_low)}–{_pct(c.ci_high)}, {c.agree}/{c.scored})",
    ]
    if report.outcomes_without_a_kronagent_call:
        lines += ["", "  outcomes for findings Kronagent never saw (not scored): "
                  + ", ".join(report.outcomes_without_a_kronagent_call)]
    if report.notes:
        lines += [""] + [f"  note: {n}" for n in report.notes]

    lines += ["", f"  disagreements ({len(report.disagreements)}):"]
    if not report.disagreements:
        lines.append("    none")
    for d in report.disagreements:
        sev = "?" if d.severity is None else f"{d.severity:.1f}"
        lines.append(
            f"    {d.finding_id}  severity {sev}  [{', '.join(d.kinds)}]  "
            f"model={'actionable' if d.model_actionable else 'not actionable'}"
            f"{' (rescued by floor)' if d.rescued_by_floor else ''}  "
            f"would_contain={d.would_contain}  "
            f"team: {d.analyst_verdict}/{d.team_action} by {d.recorded_by}"
            + (f"  — {d.note}" if d.note else ""))
    return "\n".join(lines)
