"""
Insight tags — compressed, scannable context on a pending approval.

The approval queue already carries everything a reviewer needs: the exact API
calls, the rollback plan, blast radius, MITRE mapping, campaign correlation,
evidence collected. That is thorough and it is not *scannable*. A human deciding
under incident pressure reads the first two lines and forms a judgement; the
tenth field does not reach them.

A tag is the decision-relevant part of that record, named. `IRREVERSIBLE` at a
glance is worth more than a `reversible: false` field nine lines down.

**Every tag is derived deterministically — never from a model.** That is not a
style preference. A tag is read by a human who is about to authorise something
against production, so a tag is an input to the decision. If a model produced
them, injected telemetry could emit "known false alarm" and talk a reviewer out
of containing a real breach, or "confirmed breach" to rush one through. That is
a prompt-injection path straight into the human decision — the one surface the
rest of the architecture protects. A product that only investigates can afford
model-written labels, because nothing it says ever executes. This one cannot.

So tags come from the policy classification, the finding's own structured
fields, and pipeline state. Every one is reproducible from the stored request.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import re

from pydantic import BaseModel

from .policy import action_properties
from .schemas import BlastRadius

# A planned call still carrying a placeholder, e.g. "<KRONAGENT_QUARANTINE_SG_ID
# unset>". In dry-run it renders harmlessly and is never sent; live, the call
# goes out malformed. That difference is invisible in the queue unless it is
# named, and it is discovered mid-incident otherwise.
_PLACEHOLDER = re.compile(r"<[^>]*unset[^>]*>")

RISK = "risk"                # reasons to hesitate
BLOCKER = "blocker"          # would fail or misfire if approved as-is
CONTEXT = "context"          # changes how much this matters
REASSURANCE = "reassurance"  # reasons this is safer than it looks


class InsightTag(BaseModel):
    label: str
    kind: str   # RISK | BLOCKER | CONTEXT | REASSURANCE
    why: str    # one line: what the reviewer should do with this


def insight_tags(request) -> list[InsightTag]:
    """Tags for one pending approval, most decision-relevant first.

    Ordered so a reviewer scanning left to right meets blockers, then risks,
    then context. Reassurance last: it is the least urgent thing to read and the
    most dangerous thing to lead with.
    """
    props = action_properties(request.action_class)
    tags: list[InsightTag] = []

    # --- Blockers: approving this as-is does not do what it appears to -------
    placeholders = sorted({m for call in (request.planned_api_calls or [])
                           for m in _PLACEHOLDER.findall(call)})
    if placeholders:
        tags.append(InsightTag(
            label="UNCONFIGURED",
            kind=BLOCKER,
            why=(f"a planned call still contains {placeholders[0]} — in dry-run that "
                 f"renders harmlessly, but live the call goes out malformed. Fix the "
                 f"setting before approving; `run_preflight.py` catches this."),
        ))

    # --- Risk: the cost of being wrong --------------------------------------
    if not request.reversible:
        tags.append(InsightTag(
            label="IRREVERSIBLE",
            kind=RISK,
            why="this cannot be undone. If the verdict is wrong, there is no rollback.",
        ))
    if props.get("destructive"):
        tags.append(InsightTag(
            label="DESTRUCTIVE",
            kind=RISK,
            why="takes a workload offline or destroys state. It can never be granted "
                "autonomy, which is why it is in front of you.",
        ))
    if request.blast_radius != BlastRadius.SINGLE_RESOURCE.value:
        tags.append(InsightTag(
            label=f"BLAST: {str(request.blast_radius).upper()}",
            kind=RISK,
            why="reaches beyond a single resource.",
        ))
    if not request.rollback_hint or "IRREVERSIBLE" in request.rollback_hint.upper():
        tags.append(InsightTag(
            label="NO ROLLBACK",
            kind=RISK,
            why="no rollback plan was recorded for this action.",
        ))

    # Destroying the evidence before it is preserved is the failure the
    # forensics-before-containment ordering exists to prevent. If it is missing
    # on a destructive action, say so rather than leaving it to be noticed.
    if props.get("destructive") and not request.evidence_collected:
        tags.append(InsightTag(
            label="NO EVIDENCE",
            kind=RISK,
            why="no forensic evidence was preserved, and this action destroys state. "
                "Approving loses the record of what happened.",
        ))

    # --- Context: how much this matters -------------------------------------
    if request.escalated:
        tags.append(InsightTag(
            label="ESCALATED",
            kind=CONTEXT,
            why="the incident commander flagged this for immediate attention.",
        ))
    if request.related_finding_ids:
        n = len(request.related_finding_ids)
        tags.append(InsightTag(
            label="CAMPAIGN",
            kind=CONTEXT,
            why=f"correlated with {n} prior finding{'s' if n != 1 else ''} — not an "
                f"isolated alert.",
        ))
    if request.severity < 4.0:
        tags.append(InsightTag(
            label="LOW SEVERITY",
            kind=CONTEXT,
            why=f"severity {request.severity:.1f}. Worth asking why this warrants "
                f"containment at all.",
        ))

    # --- Reassurance: why this is safer than it looks ------------------------
    if request.evidence_collected and props.get("destructive"):
        kinds = ", ".join(request.evidence_collected)
        tags.append(InsightTag(
            label="EVIDENCE PRESERVED",
            kind=REASSURANCE,
            why=f"forensics captured {kinds} before this action was proposed.",
        ))

    return tags


def tag_labels(request) -> list[str]:
    """Just the labels, for a one-line queue listing."""
    return [t.label for t in insight_tags(request)]
