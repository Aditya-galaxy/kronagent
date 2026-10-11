"""
Typed contracts for the pipeline — provider-neutral internal types.

Provider wire schemas (GuardDuty, Kubernetes audit, ...) live in their own
provider modules (kronagent/providers/*.py) and normalize into the neutral
`Finding` (kronagent/model.py). This module holds only what's shared across every
provider: the action taxonomy, triage verdict, proposed actions, policy
decisions, action outcomes, and audit records.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from .crypto import Signer


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Internal pipeline types
# --------------------------------------------------------------------------- #

class ActionClass(str, Enum):
    """Every containment capability the platform has, across all providers, as a
    stable identifier. Values double as the keys in the auto-execute allowlist,
    so the earn-trust governance is uniform: an operator promotes 'isolate_pod'
    exactly the way they promote 'disable_access_key'."""

    # --- AWS ---
    DISABLE_ACCESS_KEY = "disable_access_key"
    ATTACH_DENY_ALL_TO_PRINCIPAL = "attach_deny_all_to_principal"
    ISOLATE_INSTANCE_SG = "isolate_instance_sg"
    TERMINATE_INSTANCE = "terminate_instance"
    BLOCK_IP = "block_ip"
    REVOKE_ROLE_SESSIONS = "revoke_role_sessions"

    # --- Kubernetes ---
    ISOLATE_POD = "isolate_pod"                    # deny-all NetworkPolicy over the pod
    CORDON_NODE = "cordon_node"                    # stop new scheduling onto a node
    DELETE_POD = "delete_pod"                      # kill the pod (controller reschedules)
    SCALE_DEPLOYMENT_ZERO = "scale_deployment_zero"  # take a workload to 0 replicas

    # --- GCP ---
    DISABLE_SERVICE_ACCOUNT_KEY = "disable_service_account_key"
    DISABLE_SERVICE_ACCOUNT = "disable_service_account"
    STOP_VM_INSTANCE = "stop_vm_instance"

    # --- Azure ---
    # Deliberately distinct from the GCP compute/identity classes rather than
    # shared: the allowlist is keyed by action class alone, so reusing a class
    # across clouds would make trust earned on one cloud silently apply to
    # another. BLOCK_IP stays shared — it is already common to AWS and GCP.
    ISOLATE_VM_NSG = "isolate_vm_nsg"                  # deny-all NSG on the VM's NIC
    DEALLOCATE_VM = "deallocate_vm"                    # stop + deallocate the VM
    DISABLE_ENTRA_PRINCIPAL = "disable_entra_principal"  # disable an Entra ID user/SP
    REVOKE_ENTRA_SESSIONS = "revoke_entra_sessions"    # invalidate refresh tokens

    # --- In-house / on-premises infrastructure ---
    ISOLATE_HOST_NETWORK = "isolate_host_network"      # quarantine VLAN / NAC / host firewall
    DISABLE_LOCAL_ACCOUNT = "disable_local_account"    # disable a local or AD account
    KILL_PROCESS = "kill_process"                      # terminate a running process


class BlastRadius(str, Enum):
    SINGLE_RESOURCE = "single_resource"  # affects exactly one principal/instance/pod
    SUBNET = "subnet"                    # affects a subnet / shared NACL / node
    ACCOUNT = "account"                  # account/cluster-wide effect


class TriageVerdict(BaseModel):
    """Result of fusing GuardDuty's deterministic detection with LLM triage."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    is_actionable_threat: bool
    threat_category: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: float
    justification: str
    correlated_signals: list[str] = Field(default_factory=list)
    # True when the model said "not actionable" after reading the finding's free
    # text, but judged the structured fields alone to be a threat: the text is
    # what talked it out. A contested finding always goes to a person.
    contested: bool = False
    signature: Optional[str] = None

    def compute_signature_payload(self) -> bytes:
        import json
        payload_dict = {
            "finding_id": self.finding_id,
            "is_actionable_threat": self.is_actionable_threat,
            "threat_category": self.threat_category,
            "confidence": self.confidence,
            "severity": self.severity,
            "justification": self.justification,
            "correlated_signals": self.correlated_signals,
        }
        # Signed when set, and absent otherwise so verdicts signed before the
        # field existed still verify.
        if self.contested:
            payload_dict["contested"] = True
        return json.dumps(payload_dict, sort_keys=True).encode("utf-8")

    def with_signature(self, signer: "Signer") -> "TriageVerdict":
        import base64
        payload = self.compute_signature_payload()
        sig_bytes = signer.sign(payload)
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
        return self.model_copy(update={"signature": sig_b64})

    def verify_signature(self, signer: "Signer") -> bool:
        import base64
        if not self.signature:
            return False
        try:
            sig_bytes = base64.b64decode(self.signature)
            payload = self.compute_signature_payload()
            return signer.verify(payload, sig_bytes)
        except Exception:
            return False


class ProposedAction(BaseModel):
    """A single containment step the triage/response layer wants to take."""

    model_config = ConfigDict(frozen=True)

    provider: str                  # which containment adapter owns this action
    # Whose account this action runs against. Stamped centrally by
    # providers.plan_actions from the finding, never set by a planner and never
    # by a model — executing one tenant's containment with another tenant's
    # credentials is the worst failure this system could have.
    tenant_id: str = "default"
    action_class: ActionClass
    target: str                    # the concrete resource id / arn / ip / pod
    rationale: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    disposition: Literal["auto_execute", "requires_approval", "blocked"]
    reason: str
    reversible: bool
    blast_radius: BlastRadius


class ActionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    target: str
    executed: bool           # False when dry-run or awaiting approval
    dry_run: bool
    detail: str
    rollback_hint: str       # exactly how to reverse this action
    api_calls: list[str] = Field(default_factory=list)  # the concrete calls made / planned
    error: Optional[str] = None


class ReleaseOutcome(BaseModel):
    """What happened when a person asked for a containment action to be undone."""

    model_config = ConfigDict(frozen=True)

    action_class: ActionClass
    target: str
    released: bool           # False in dry-run, when unsupported, and on failure
    dry_run: bool
    supported: bool = True   # False: Kronagent can't run this release; the hint is for a person
    detail: str
    api_calls: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class AuditRecord(BaseModel):
    """One immutable audit entry. Hash-chained in the audit log."""

    model_config = ConfigDict(extra="allow")

    ts: str = Field(default_factory=utcnow_iso)
    finding_id: str
    stage: str               # "triage" | "policy" | "containment"
    payload: dict[str, Any]
