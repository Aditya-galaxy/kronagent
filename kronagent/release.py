"""
What Kronagent has contained, and which of it a person has released.

A containment action is recorded twice in the audit log: the policy record
carries the action as it was planned (provider, tenant, target, parameters),
and the containment record says whether it ran. This module joins them into
the list a person needs when something has to be undone: every action that ran,
whether the policy engine or an approver let it, and whether it has been
released since.

That list is also what bounds a release. `approve.py release` can only undo an
action found here. The target and its parameters come from the audit record of
what Kronagent did, never from the command line, so a release cannot be aimed at
a key or an address Kronagent never touched.

Nothing in the pipeline calls a release, and nothing releases on a timer:
containment that nobody has reviewed stays in place (see unconfirmed.py for
why). A release is a person's decision, with a reason, audited before it runs.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Iterable, Optional

from pydantic import BaseModel

from .schemas import ProposedAction


class Containment(BaseModel):
    finding_id: str
    action: ProposedAction
    at: str = ""
    executed: bool                       # False: dry-run, it would have run
    approved_request: Optional[str] = None   # set when a person approved it; None when policy let it run
    released_at: Optional[str] = None
    released_by: Optional[str] = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.finding_id, self.action.action_class.value, self.action.target)


def containments_from_audit(records: Iterable[dict], *, include_dry_run: bool = False) -> list[Containment]:
    """Every containment action that ran, in the order it ran, each marked
    released if a later release record covers it. With `include_dry_run`, also
    the ones dry-run would have run, so the release path can be rehearsed
    before anything is live."""
    planned: dict[tuple[str, str, str], ProposedAction] = {}
    found: list[Containment] = []
    for rec in records:
        stage, fid = rec.get("stage"), rec.get("finding_id")
        payload = rec.get("payload") or {}
        if not fid:
            continue
        if stage == "policy":
            raw = payload.get("action") or {}
            try:
                action = ProposedAction(**raw)
            except (TypeError, ValueError):
                continue                 # a record this old or this damaged plans nothing we can undo
            planned[(fid, action.action_class.value, action.target)] = action
        elif stage == "containment":
            key = (fid, str(payload.get("action_class") or ""), str(payload.get("target") or ""))
            ran = payload.get("executed") is True
            would = (not ran and payload.get("dry_run") is True
                     and str(payload.get("detail") or "").startswith("DRY-RUN"))
            if key in planned and (ran or (include_dry_run and would)):
                found.append(Containment(finding_id=fid, action=planned[key], at=rec.get("ts", ""),
                                         executed=ran, approved_request=payload.get("request_id")))
        elif stage == "release" and payload.get("released") is True:
            key = (fid, str(payload.get("action_class") or ""), str(payload.get("target") or ""))
            for c in reversed(found):
                if c.key == key and c.released_at is None:
                    c.released_at = rec.get("ts", "") or "unknown"
                    c.released_by = payload.get("operator_id") or payload.get("by")
                    break
    return found
