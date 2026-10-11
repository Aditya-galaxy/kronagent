"""
Promotion evidence: how often would this action class have been wrong?

Promoting an action class to autonomous execution has been a judgement: an
operator gives a reason, and the reason is audited. Shadow mode already holds
something better than a reason. For every finding it records what Kronagent
planned, and `outcome.py record` stores what the team decided. Put together,
they answer the question a promotion is really asking:

    Of the findings where Kronagent would have run this action unattended,
    how many did the team judge benign, or choose not to contain?

That count gives a bound, not just a rate. With `n` scored findings and `k` of
them unwarranted, the exact binomial upper bound says: "with 95% confidence,
fewer than X% of these actions would have been wrong." Twenty clean findings
sound convincing and only show the rate is below 14%. Fifty-nine show it is
below 5%. The number of findings a promotion needs follows from the error the
operator will accept, and this module says how many are still missing.

What counts, and what does not:

  * Only findings the triage model itself called actionable. A finding the
    model dismissed and the severity floor (or the structured-fields recheck)
    sent to a person is forced to approval whatever the allowlist says, so a
    promotion would never run it unattended.
  * Only planned actions on a provider the promotion would cover.
  * **Unwarranted** is conservative in both directions: the analyst's verdict
    was benign, *or* the team took no containment action. Either one means an
    unattended action would have done something nobody chose.
  * Findings with no recorded outcome, or an inconclusive one, are left out and
    counted, never treated as agreement.

What the bound does not cover, stated wherever it is shown:

  * An outcome is recorded per finding, not per action. "The team contained
    it" does not say they would have used this exact action.
  * The bound assumes next month's findings resemble the ones scored. An
    attacker who knows a class is autonomous can change what arrives. That is
    why a promotion still carries an owner and an expiry: the evidence earns
    the autonomy, the expiry makes it be earned again.
  * Evidence is per tenant and per provider. It is not yet per AWS account.

The same records also take autonomy away. `unwarranted_autonomy` finds promoted
classes that ran unattended on a finding the team then judged unwarranted, and
the allowlist suspends them (AllowlistStore.suspend_unwarranted) until someone
renews them. Evidence can end a promotion on its own; only a person can make one.

Nothing here changes a decision on a finding. It reads records already written.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Optional

from pydantic import BaseModel, Field

from .outcomes import AnalystOutcome
from .shadow import KronagentCall
from .stats import binomial_upper_bound, clean_trials_needed

if TYPE_CHECKING:
    from .allowlist import AllowlistEntry

DEFAULT_CONFIDENCE = 0.95


class Unwarranted(BaseModel):
    finding_id: str
    severity: Optional[float] = None
    analyst_verdict: str
    team_action: str
    recorded_by: str
    note: str = ""


class ActionEvidence(BaseModel):
    action_class: str
    providers: Optional[list[str]] = None        # None: every provider
    since: Optional[str] = None
    confidence: float = DEFAULT_CONFIDENCE
    planned: int = 0             # findings where this action would have run unattended once promoted
    scored: int = 0              # of those, with a conclusive recorded outcome
    warranted: int = 0
    unwarranted: int = 0
    unlabeled: int = 0
    inconclusive: int = 0
    revised_outcomes: int = 0
    error_upper_bound: float = 1.0
    max_error: Optional[float] = None            # the bar, when one is set
    meets_bar: Optional[bool] = None
    clean_findings_still_needed: Optional[int] = None
    unwarranted_findings: list[Unwarranted] = Field(default_factory=list)

    def statement(self) -> str:
        scope = self.action_class + (f" on {', '.join(self.providers)}" if self.providers else "")
        if self.scored == 0:
            return (f"No scored findings for {scope}: nothing has been shown about how often it "
                    f"would have been wrong.")
        return (f"With {self.confidence:.0%} confidence, fewer than {self.error_upper_bound:.1%} of "
                f"unattended {scope} actions would have been unwarranted "
                f"({self.unwarranted} of {self.scored} scored findings were).")


def build_evidence(calls: dict[str, KronagentCall], outcomes: Iterable[AnalystOutcome], action_class: str, *,
                   providers: Optional[Iterable[str]] = None, max_error: Optional[float] = None,
                   confidence: float = DEFAULT_CONFIDENCE, since: Optional[str] = None) -> ActionEvidence:
    scope = sorted(set(providers)) if providers else None
    by_finding = {o.finding_id: o for o in outcomes}
    ev = ActionEvidence(action_class=action_class, providers=scope, since=since, confidence=confidence,
                        max_error=max_error)

    for fid in sorted(calls, key=lambda f: (calls[f].first_seen, f)):
        call = calls[fid]
        if since and call.first_seen and call.first_seen < since:
            continue
        # Dismissed by the model and sent to a person anyway: never unattended.
        if not call.model_actionable or call.rescued_by_floor:
            continue
        if not any(cls == action_class and (scope is None or provider in scope)
                   for cls, provider in call.planned_actions):
            continue
        ev.planned += 1
        outcome = by_finding.get(fid)
        if outcome is None:
            ev.unlabeled += 1
            continue
        if outcome.verdict == "inconclusive":
            ev.inconclusive += 1
            continue
        ev.scored += 1
        ev.revised_outcomes += outcome.revision > 1
        if outcome.verdict == "benign" or outcome.team_action == "no_action":
            ev.unwarranted += 1
            ev.unwarranted_findings.append(Unwarranted(
                finding_id=fid, severity=call.severity, analyst_verdict=outcome.verdict,
                team_action=outcome.team_action, recorded_by=outcome.recorded_by, note=outcome.note))
        else:
            ev.warranted += 1

    ev.error_upper_bound = binomial_upper_bound(ev.unwarranted, ev.scored, confidence)
    if max_error is not None:
        ev.meets_bar = ev.scored > 0 and ev.error_upper_bound <= max_error
        if not ev.meets_bar:
            ev.clean_findings_still_needed = _still_needed(ev.unwarranted, ev.scored, max_error, confidence)
    return ev


def unwarranted_autonomy(calls: dict[str, KronagentCall], outcomes: Iterable[AnalystOutcome],
                         entries: Iterable["AllowlistEntry"]) -> dict[str, list[str]]:
    """Promoted action classes that ran unattended on a finding the team then
    judged unwarranted: {action_class: [finding ids]}.

    This is the evidence that takes autonomy away. Three conditions, all needed:

      * the policy engine's disposition for that action was auto_execute, on a
        provider the entry covers. An action a person approved is that person's
        decision, not the entry's;
      * the finding arrived after the entry was promoted or last renewed. A
        renewal is a fresh decision made knowing the record, so an old finding
        can't undo it;
      * the recorded outcome is conclusive and unwarranted: the verdict was
        benign, or the team took no action.
    """
    from .allowlist import parse_ts

    by_finding = {o.finding_id: o for o in outcomes}
    found: dict[str, list[str]] = {}
    for entry in entries:
        if entry.is_expired() or entry.is_suspended:
            continue
        since = parse_ts(entry.promoted_at)
        for fid in sorted(calls, key=lambda f: (calls[f].first_seen, f)):
            call, outcome = calls[fid], by_finding.get(fid)
            if outcome is None or outcome.verdict == "inconclusive":
                continue
            if not (outcome.verdict == "benign" or outcome.team_action == "no_action"):
                continue
            if not any(cls == entry.action_class and entry.covers(provider)
                       for cls, provider in call.unattended_actions):
                continue
            seen = parse_ts(call.first_seen)
            if since is not None and (seen is None or seen < since):
                continue
            found.setdefault(entry.action_class, []).append(fid)
    return found


def _still_needed(unwarranted: int, scored: int, max_error: float, confidence: float) -> int:
    """More findings, all warranted, before the bound drops to the bar."""
    if unwarranted == 0:
        return max(0, clean_trials_needed(max_error, confidence) - scored)
    extra = 1
    while binomial_upper_bound(unwarranted, scored + extra, confidence) > max_error:
        extra *= 2
    low, high = extra // 2, extra
    while low + 1 < high:
        mid = (low + high) // 2
        if binomial_upper_bound(unwarranted, scored + mid, confidence) > max_error:
            low = mid
        else:
            high = mid
    return high


def render_text(ev: ActionEvidence) -> str:
    """Every unwarranted finding is printed. Evidence shown without its losses
    is an advertisement."""
    lines = [f"Promotion evidence — {ev.action_class}"
             + (f" on {', '.join(ev.providers)}" if ev.providers else " (every provider)")
             + (f", since {ev.since}" if ev.since else ""), "",
             f"  would have run unattended   {ev.planned}",
             f"  scored                      {ev.scored}   (warranted {ev.warranted}, "
             f"unwarranted {ev.unwarranted})",
             f"  no outcome recorded         {ev.unlabeled}   (left out, not counted as agreement)",
             f"  inconclusive                {ev.inconclusive}   (left out)",
             "", f"  {ev.statement()}"]
    if ev.max_error is not None:
        if ev.meets_bar:
            lines.append(f"  That is within the bar of {ev.max_error:.1%}.")
        else:
            lines.append(f"  The bar is {ev.max_error:.1%}: NOT MET. It would take "
                         f"{ev.clean_findings_still_needed} more scored finding(s), all warranted, "
                         f"to meet it.")
    if ev.revised_outcomes:
        lines.append(f"  note: {ev.revised_outcomes} of the scored outcomes were revised after "
                     f"first being recorded.")
    lines += ["", "  note: outcomes are recorded per finding, not per action, and the bound assumes "
              "future findings", "        resemble these. It is evidence for a promotion with an "
              "owner and an expiry, not instead of them.",
              "", f"  unwarranted ({len(ev.unwarranted_findings)}):"]
    if not ev.unwarranted_findings:
        lines.append("    none")
    for u in ev.unwarranted_findings:
        sev = "?" if u.severity is None else f"{u.severity:.1f}"
        lines.append(f"    {u.finding_id}  severity {sev}  team: {u.analyst_verdict}/{u.team_action} "
                     f"by {u.recorded_by}" + (f"  — {u.note}" if u.note else ""))
    return "\n".join(lines)
