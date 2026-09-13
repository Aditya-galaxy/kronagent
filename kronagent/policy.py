"""
Graduated-autonomy policy engine.

This is the gate between "the response layer proposed an action" and "the
platform is allowed to execute it autonomously." It is deliberately pure,
deterministic logic driven only by the finding's severity and the action
class's intrinsic properties — no LLM, so its decisions cannot be influenced
by prompt injection in the telemetry. The one piece of I/O is a read of the
persisted, audited AllowlistStore (see allowlist.py) — every decision reflects
the allowlist as it stands *right now*, so a promotion/demotion takes effect
immediately with no restart.

Decision procedure for each proposed action:

  1. Kill switch on              -> blocked
  2. Below containment severity  -> blocked (alert-only)
  3. Look up the action class's intrinsic properties (reversible?, blast radius).
  4. An action is AUTO_ELIGIBLE iff it is reversible AND single-resource AND
     not in the intrinsically-destructive set.
  5. It actually auto-executes iff it is AUTO_ELIGIBLE **and** its class has a
     live (unexpired) entry in the AllowlistStore (earn-trust).
  6. Otherwise -> requires_approval.

The allowlist is the earn-trust dial: it starts empty (everything needs a
human), and operators promote one action class at a time — via promote.py,
never a direct edit — as it proves safe. Every promotion/demotion is written
to the hash-chained audit log with who did it and why.

The dial turns back on its own, too. A promotion may carry a TTL, and step 5
reads through `is_allowed()`, which refuses an entry whose TTL has lapsed. So
expiry demotes a class at the gate on the very next decision — nothing here
waits on a sweep, a cron, or a restart to withdraw autonomy.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Optional

from .allowlist import AllowlistStore
from .config import Settings
from .classification import _ACTION_PROPERTIES, action_properties  # noqa: F401 — re-exported
from .identity import owner_vacancy_checker
from .schemas import ActionClass, BlastRadius, PolicyDecision, ProposedAction


class PolicyEngine:
    def __init__(self, settings: Settings, allowlist: AllowlistStore) -> None:
        self._settings = settings
        self._allowlist = allowlist

    def _properties(self, action_class: ActionClass) -> dict:
        # Unknown action classes default to the most restrictive posture.
        return action_properties(action_class)

    def is_auto_eligible(self, action_class: ActionClass) -> bool:
        p = self._properties(action_class)
        return (
            p["reversible"]
            and p["blast_radius"] == BlastRadius.SINGLE_RESOURCE
            and not p["destructive"]
        )

    def decide(
        self,
        action: ProposedAction,
        *,
        severity: float,
        allowlist: Optional[AllowlistStore] = None
    ) -> PolicyDecision:
        s = self._settings
        props = self._properties(action.action_class)
        reversible = props["reversible"]
        blast = props["blast_radius"]

        if s.kill_switch:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="blocked",
                reason="kill switch engaged — all containment halted",
                reversible=reversible,
                blast_radius=blast,
            )

        if severity < s.min_severity_for_containment:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="blocked",
                reason=(
                    f"severity {severity:.1f} below containment threshold "
                    f"{s.min_severity_for_containment:.1f} — alert only"
                ),
                reversible=reversible,
                blast_radius=blast,
            )

        actual_allowlist = allowlist if allowlist is not None else self._allowlist
        auto_eligible = self.is_auto_eligible(action.action_class)
        # Owner standing is checked against the tenant the action runs in —
        # stamped from the finding, never by a planner or model — because an
        # owner can keep their job and still lose access to this customer.
        owner_check = owner_vacancy_checker(s.operator_registry_path, action.tenant_id)
        allowlisted, entry_refusal = actual_allowlist.evaluate(
            action.action_class, owner_check=owner_check,
        )

        if auto_eligible and allowlisted:
            return PolicyDecision(
                action_class=action.action_class,
                disposition="auto_execute",
                reason="reversible, single-resource, and operator-allowlisted for autonomy",
                reversible=reversible,
                blast_radius=blast,
            )

        if not auto_eligible:
            reason = "destructive or wide blast radius — human approval required"
        elif entry_refusal:
            # Say why an entry that exists does not count. "Not allowlisted"
            # would send the approver to promote a class that is already
            # promoted, and hide that its owner has gone.
            reason = f"auto-eligible, but {entry_refusal} — human approval required"
        else:
            reason = "auto-eligible but not yet in the earn-trust allowlist — human approval required"

        return PolicyDecision(
            action_class=action.action_class,
            disposition="requires_approval",
            reason=reason,
            reversible=reversible,
            blast_radius=blast,
        )
