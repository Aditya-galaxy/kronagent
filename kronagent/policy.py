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
from .schemas import ActionClass, BlastRadius, PolicyDecision, ProposedAction

# Intrinsic properties of each containment capability. This table is the
# security-reviewed classification of "how dangerous is this action" and is the
# single source of truth the auto/approval decision is derived from.
_ACTION_PROPERTIES: dict[ActionClass, dict] = {
    ActionClass.DISABLE_ACCESS_KEY: {
        "reversible": True,   # re-activate the key
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.ISOLATE_INSTANCE_SG: {
        "reversible": True,   # restore the instance's original security groups
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.BLOCK_IP: {
        "reversible": True,   # remove the deny rule from the quarantine group
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL: {
        "reversible": True,   # detach the inline deny policy
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.REVOKE_ROLE_SESSIONS: {
        # Reversible in the sense that new sessions can be issued, but it
        # forcibly kills in-flight legitimate sessions too -> treat as
        # destructive so it never auto-executes.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
    ActionClass.TERMINATE_INSTANCE: {
        "reversible": False,  # cannot un-terminate an instance
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },

    # --- Kubernetes ---
    ActionClass.ISOLATE_POD: {
        "reversible": True,   # remove the label + delete the NetworkPolicy
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.CORDON_NODE: {
        # Non-disruptive: stops NEW scheduling only, running pods untouched;
        # fully reversible via uncordon. Node-scoped but low-impact.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.DELETE_POD: {
        # A controller reschedules a replacement, but the running process is
        # killed -> disruptive; gate behind approval.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
    ActionClass.SCALE_DEPLOYMENT_ZERO: {
        # Reversible (scale back up) but takes the whole workload down ->
        # destructive; approval-gated.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },

    # --- GCP ---
    ActionClass.DISABLE_SERVICE_ACCOUNT_KEY: {
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.DISABLE_SERVICE_ACCOUNT: {
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.STOP_VM_INSTANCE: {
        # Reclassified 2026-07-29 from destructive=False. Stopping a VM takes a
        # running workload offline and discards volatile memory — the same shape
        # as SCALE_DEPLOYMENT_ZERO and the Azure DEALLOCATE_VM, both of which are
        # destructive. It was the only "workload goes down" action classified as
        # auto-eligible, which meant a single allowlist entry could stop GCP
        # production VMs unattended while the identical Azure action required a
        # human. Discarding volatile memory also destroys the evidence the
        # forensics stage runs first to preserve.
        #
        # BEHAVIOUR CHANGE: an operator who had promoted stop_vm_instance now
        # sees it routed to approval. That is the intended direction — the
        # policy table is the ceiling, and this raises it.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },

    # --- Azure ---
    ActionClass.ISOLATE_VM_NSG: {
        # Preferred Azure containment: the VM keeps running (preserving volatile
        # memory for forensics) but cannot talk to anything. Restore the NIC's
        # original NSG to roll back.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.DEALLOCATE_VM: {
        # Reversible (start it again) but it takes a running workload offline
        # and discards volatile state -> destructive, so it is approval-gated
        # regardless of the allowlist. Classified the same way as
        # SCALE_DEPLOYMENT_ZERO, which has the same "workload goes down" shape.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
    ActionClass.DISABLE_ENTRA_PRINCIPAL: {
        "reversible": True,   # re-enable the principal
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.REVOKE_ENTRA_SESSIONS: {
        # Same reasoning as REVOKE_ROLE_SESSIONS: new sessions can be issued,
        # but this forcibly kills in-flight legitimate sessions too.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },

    # --- In-house / on-premises ---
    ActionClass.ISOLATE_HOST_NETWORK: {
        # The on-prem analogue of ISOLATE_INSTANCE_SG: move the host to a
        # quarantine VLAN / deny-all NAC policy. The box stays powered on for
        # forensics; restoring its original VLAN rolls it back.
        "reversible": True,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.DISABLE_LOCAL_ACCOUNT: {
        "reversible": True,   # re-enable the account
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": False,
    },
    ActionClass.KILL_PROCESS: {
        # Irreversible in any meaningful sense — the process and its in-memory
        # state are gone, which can also destroy evidence. Never auto-executes.
        "reversible": False,
        "blast_radius": BlastRadius.SINGLE_RESOURCE,
        "destructive": True,
    },
}



def action_properties(action_class: ActionClass) -> dict:
    """The intrinsic classification of one action class, for callers outside the
    decision path (the approval UI, insight tags).

    Public so nothing has to reach into `_ACTION_PROPERTIES`, and so the
    unknown-class default stays in one place: maximally dangerous, matching what
    the engine itself assumes.
    """
    return _ACTION_PROPERTIES.get(
        action_class,
        {"reversible": False, "blast_radius": BlastRadius.ACCOUNT, "destructive": True},
    )


class PolicyEngine:
    def __init__(self, settings: Settings, allowlist: AllowlistStore) -> None:
        self._settings = settings
        self._allowlist = allowlist

    def _properties(self, action_class: ActionClass) -> dict:
        # Unknown action classes default to the most restrictive posture.
        return _ACTION_PROPERTIES.get(
            action_class,
            {"reversible": False, "blast_radius": BlastRadius.ACCOUNT, "destructive": True},
        )

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
        allowlisted = actual_allowlist.is_allowed(action.action_class)

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
        else:
            reason = "auto-eligible but not yet in the earn-trust allowlist — human approval required"

        return PolicyDecision(
            action_class=action.action_class,
            disposition="requires_approval",
            reason=reason,
            reversible=reversible,
            blast_radius=blast,
        )
