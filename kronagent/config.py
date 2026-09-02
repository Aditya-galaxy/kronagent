"""
Platform configuration and the safety-critical control switches.

Every field that governs whether the platform can touch production
infrastructure lives here, defaults to the *safe* value, and is overridable
from the environment. The two load-bearing safety controls are:

  * dry_run           — when True (the default), NO containment action is
                        actually executed; the platform produces the exact
                        API calls it *would* make and records them.
  * kill_switch       — when True, the platform halts all containment
                        entirely (not even dry-run planning proceeds to
                        execution). A single global stop.

Graduated autonomy is expressed by the allowlist (see allowlist.py): an action
class executes automatically ONLY if it is (a) classified AUTO_ELIGIBLE by the
policy engine AND (b) explicitly present in the allowlist. The allowlist is a
persisted, audited store — promote/demote it with promote.py, not by editing
this file or its env var. `auto_execute_allowlist` below is consulted ONLY to
seed that store the first time it's created (so an existing deployment isn't
silently reset to empty); once the store file exists, this env var is ignored.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


# Settings were prefixed with the previous product name before the rename.
# Read the current prefix first and fall back to the legacy one, so an existing
# .env or a deployed config keeps working instead of silently reverting to
# defaults — a silent revert here would re-enable dry-run or drop the
# allowlist without anyone noticing.
#
# The legacy prefix is assembled rather than written as a literal: a naive
# find-and-replace across the repo would otherwise rewrite it to the new
# prefix and turn this whole function into a no-op. That is not hypothetical.
_PREFIX = "KRONAGENT_"
_LEGACY_PREFIX = "AEG" + "IS_"


class ConfigError(ValueError):
    """Raised when platform configuration is invalid or unsafe."""
    pass



def _getenv(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    if val is not None:
        return val
    if name.startswith(_PREFIX):
        legacy = os.environ.get(_LEGACY_PREFIX + name[len(_PREFIX):])
        if legacy is not None:
            return legacy
    return default


def _env_bool(name: str, default: bool) -> bool:
    raw = _getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_set(name: str) -> frozenset[str]:
    raw = _getenv(name, "") or ""
    return frozenset(x.strip() for x in raw.split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    # --- Safety controls (fail safe) ---
    dry_run: bool = True
    kill_switch: bool = False
    # First-run seed only — see the module docstring. Live state lives in
    # AllowlistStore at allowlist_store_path; manage it with promote.py.
    auto_execute_allowlist: frozenset[str] = field(default_factory=frozenset)

    # Findings at or above this GuardDuty severity are eligible for
    # autonomous containment at all; below it, the platform only alerts.
    min_severity_for_containment: float = 4.0

    # --- AWS ---
    aws_region: str = "us-east-1"
    # Name of the pre-provisioned, deny-all quarantine security group used for
    # EC2 isolation. Created once by ops, referenced here.
    quarantine_security_group_id: str = ""
    # ID of the pre-provisioned, quarantine network ACL used for blocking IPs.
    quarantine_nacl_id: str = ""
    # Optional SQS endpoint override. Empty = the real AWS endpoint. Set it to
    # point the SQS ingestion at a local emulator (moto server / ElasticMQ) for
    # the testbed, or at a VPC/PrivateLink SQS endpoint in production. This is
    # the one knob that lets the *live* ingestion path run with no AWS account.
    sqs_endpoint_url: str = ""
    # SQS long-poll wait (seconds). 20 (the AWS max) is the right production
    # default — fewer empty receives, lower cost. Lower it for fast shutdown
    # responsiveness (an in-flight long-poll can't be interrupted by the stop
    # signal, so this bounds shutdown latency) — the testbed/demo use ~2.
    sqs_wait_seconds: int = 20
    # How often to poll GuardDuty through a connected tenant's assumed role.
    # Polling is the zero-provisioning ingestion path: the observe role already
    # grants ListFindings/GetFindings, so a verified connection starts producing
    # findings with no queue, rule or IAM beyond what the customer already
    # granted. 60s trades latency for that, which is the right call in shadow
    # mode; use the SQS path when seconds matter.
    guardduty_poll_seconds: float = 60.0

    # --- Kubernetes ---
    # Empty kubeconfig_path uses the default resolution (KUBECONFIG / ~/.kube/config
    # / in-cluster). Empty context uses the current-context.
    kubeconfig_path: str = ""
    kube_context: str = ""

    # --- Azure ---
    azure_subscription_id: str = ""
    # Pre-provisioned deny-all NSG used to isolate a VM's NIC and to hold
    # block_ip deny rules. Created once by ops; Kronagent references it by id
    # and never creates one.
    azure_quarantine_nsg_id: str = ""

    # --- In-house / on-premises ---
    # Base URL of the customer's containment control plane (NAC, automation
    # runner, firewall API). Empty = on-prem containment can plan but not
    # execute; perform() fails loudly rather than silently no-op'ing.
    onprem_control_plane_url: str = ""
    # VLAN a quarantined host is moved into. Pre-provisioned by ops.
    onprem_quarantine_vlan: str = ""

    # --- Audit, approvals & governance ---
    audit_log_path: str = "kronagent_audit.jsonl"
    approval_store_path: str = "kronagent_approvals.json"
    allowlist_store_path: str = "kronagent_allowlist.json"
    # How far ahead `promote.py warn-expiring` looks when telling owners their
    # grant of autonomy is about to lapse. Long enough that renewing is a
    # considered decision rather than a scramble; the lapse itself is
    # fail-closed either way, so this only affects notice, never authority.
    allowlist_warn_within: str = "14d"
    # Tenant cloud connections. Holds External IDs, which are secrets — the
    # store creates this 0600 and re-asserts it on every write.
    connection_store_path: str = "kronagent_connections.json"
    # Operator registry for identity + RBAC. Empty (default) = unauthenticated
    # mode: approvals/promotions use free-text --by and are audited as
    # identity_verified=false. Point this at a registry (see operators.py /
    # kronagent.identity) to enforce authenticated, authorized, non-repudiable
    # operator decisions.
    operator_registry_path: str = ""
    db_path: str = ""
    max_workers: int = 1
    kms_key_id: str = ""
    require_agent_signatures: bool = False
    require_view_auth: bool = False

    # --- Behavioral-trajectory guard (the automatic kill switch) ---
    # Kronagent is itself an autonomous agent system holding production credentials.
    # This guard watches Kronagent's OWN action stream — not the telemetry it
    # ingests — and latches a halt on a runaway burst of autonomous executions
    # or repeated out-of-scope targeting (an action-redirection attack). It is
    # deterministic (no LLM), so the backstop itself cannot be prompt-injected.
    # On by default; scope enforcement blocks any action aimed at a resource not
    # implicated by its own finding.
    trajectory_guard_enabled: bool = True
    # Where a latched halt is persisted. A halt MUST outlive the process —
    # an in-memory-only latch is released by any restart, including one caused
    # by the incident that tripped it, which would turn the kill switch into a
    # suggestion. This file is also the seam `halt.py` uses to clear a halt in
    # a running deployment without a restart. Empty = in-memory only (the halt
    # does not survive a restart and no CLI can clear it).
    trajectory_state_path: str = "kronagent_trajectory_halt.json"
    trajectory_window_seconds: float = 60.0
    trajectory_max_auto_executions: int = 25
    trajectory_max_scope_violations: int = 3
    trajectory_enforce_scope: bool = True

    # --- OIDC / SAML SSO ---
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_uri: str = ""
    oidc_verify_signature: bool = True
    oidc_roles_claim: str = "roles"

    # --- ChatOps (Slack / Teams) ---
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_channel_id: str = ""
    slack_user_mapping: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Settings":
        approval_path = os.getenv("KRONAGENT_APPROVAL_PATH", "kronagent_approvals.json")
        db_path = os.getenv("KRONAGENT_DB_PATH", "")
        if not db_path and approval_path.endswith(".db"):
            db_path = approval_path

        slack_user_mapping_str = os.getenv("KRONAGENT_SLACK_USER_MAPPING", "")
        slack_user_mapping = {}
        if slack_user_mapping_str:
            try:
                slack_user_mapping = json.loads(slack_user_mapping_str)
            except json.JSONDecodeError:
                pass

        return cls(
            dry_run=_env_bool("KRONAGENT_DRY_RUN", True),
            kill_switch=_env_bool("KRONAGENT_KILL_SWITCH", False),
            auto_execute_allowlist=_env_set("KRONAGENT_AUTO_EXECUTE_ALLOWLIST"),
            min_severity_for_containment=float(
                os.getenv("KRONAGENT_MIN_SEVERITY", "4.0")
            ),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            quarantine_security_group_id=os.getenv("KRONAGENT_QUARANTINE_SG_ID", ""),
            quarantine_nacl_id=os.getenv("KRONAGENT_QUARANTINE_NACL_ID", ""),
            sqs_endpoint_url=os.getenv("KRONAGENT_SQS_ENDPOINT_URL", ""),
            sqs_wait_seconds=int(os.getenv("KRONAGENT_SQS_WAIT_SECONDS", "20")),
            guardduty_poll_seconds=float(os.getenv("KRONAGENT_GUARDDUTY_POLL_SECONDS", "60")),
            kubeconfig_path=os.getenv("KRONAGENT_KUBECONFIG", ""),
            kube_context=os.getenv("KRONAGENT_KUBE_CONTEXT", ""),
            azure_subscription_id=os.getenv("KRONAGENT_AZURE_SUBSCRIPTION_ID", ""),
            azure_quarantine_nsg_id=os.getenv("KRONAGENT_AZURE_QUARANTINE_NSG_ID", ""),
            onprem_control_plane_url=os.getenv("KRONAGENT_ONPREM_CONTROL_PLANE_URL", ""),
            onprem_quarantine_vlan=os.getenv("KRONAGENT_ONPREM_QUARANTINE_VLAN", ""),
            audit_log_path=os.getenv("KRONAGENT_AUDIT_PATH", "kronagent_audit.jsonl"),
            approval_store_path=approval_path,
            allowlist_store_path=os.getenv("KRONAGENT_ALLOWLIST_PATH", "kronagent_allowlist.json"),
            allowlist_warn_within=os.getenv("KRONAGENT_ALLOWLIST_WARN_WITHIN", "14d"),
            connection_store_path=os.getenv("KRONAGENT_CONNECTION_PATH", "kronagent_connections.json"),
            operator_registry_path=os.getenv("KRONAGENT_OPERATOR_REGISTRY", ""),
            db_path=db_path,
            max_workers=int(os.getenv("KRONAGENT_MAX_WORKERS", "1")),
            kms_key_id=os.getenv("KRONAGENT_KMS_KEY_ID", ""),
            require_agent_signatures=_env_bool("KRONAGENT_REQUIRE_AGENT_SIGNATURES", False),
            require_view_auth=_env_bool("KRONAGENT_REQUIRE_VIEW_AUTH", False),
            trajectory_guard_enabled=_env_bool("KRONAGENT_TRAJECTORY_GUARD", True),
            trajectory_state_path=os.getenv(
                "KRONAGENT_TRAJECTORY_STATE_PATH", "kronagent_trajectory_halt.json"),
            trajectory_window_seconds=float(os.getenv("KRONAGENT_TRAJECTORY_WINDOW_SECONDS", "60")),
            trajectory_max_auto_executions=int(os.getenv("KRONAGENT_TRAJECTORY_MAX_AUTO", "25")),
            trajectory_max_scope_violations=int(os.getenv("KRONAGENT_TRAJECTORY_MAX_SCOPE_VIOLATIONS", "3")),
            trajectory_enforce_scope=_env_bool("KRONAGENT_TRAJECTORY_ENFORCE_SCOPE", True),
            oidc_issuer=os.getenv("KRONAGENT_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("KRONAGENT_OIDC_AUDIENCE", ""),
            oidc_jwks_uri=os.getenv("KRONAGENT_OIDC_JWKS_URI", ""),
            oidc_verify_signature=_env_bool("KRONAGENT_OIDC_VERIFY_SIGNATURE", True),
            oidc_roles_claim=os.getenv("KRONAGENT_OIDC_ROLES_CLAIM", "roles"),
            slack_bot_token=os.getenv("KRONAGENT_SLACK_BOT_TOKEN", ""),
            slack_signing_secret=os.getenv("KRONAGENT_SLACK_SIGNING_SECRET", ""),
            slack_channel_id=os.getenv("KRONAGENT_SLACK_CHANNEL_ID", ""),
            slack_user_mapping=slack_user_mapping,
        )

    def validate(self) -> list[str]:
        """Validate configuration settings and return a list of actionable error strings."""
        errors: list[str] = []
        if self.guardduty_poll_seconds < 5:
            errors.append(
                f"KRONAGENT_GUARDDUTY_POLL_SECONDS ({self.guardduty_poll_seconds}) must be "
                f"at least 5 — GuardDuty is rate-limited and a tighter loop would "
                f"throttle the customer's account.")
        if self.sqs_wait_seconds < 0 or self.sqs_wait_seconds > 20:
            errors.append(f"KRONAGENT_SQS_WAIT_SECONDS ({self.sqs_wait_seconds}) must be between 0 and 20.")
        if self.min_severity_for_containment < 0.0 or self.min_severity_for_containment > 10.0:
            errors.append(f"KRONAGENT_MIN_SEVERITY ({self.min_severity_for_containment}) must be between 0.0 and 10.0.")
        if self.max_workers < 1:
            errors.append(f"KRONAGENT_MAX_WORKERS ({self.max_workers}) must be at least 1.")
        if self.trajectory_window_seconds <= 0:
            errors.append(f"KRONAGENT_TRAJECTORY_WINDOW_SECONDS ({self.trajectory_window_seconds}) must be positive.")
        if self.trajectory_max_auto_executions < 1:
            errors.append(f"KRONAGENT_TRAJECTORY_MAX_AUTO ({self.trajectory_max_auto_executions}) must be at least 1.")
        if self.trajectory_max_scope_violations < 1:
            errors.append(f"KRONAGENT_TRAJECTORY_MAX_SCOPE_VIOLATIONS ({self.trajectory_max_scope_violations}) must be at least 1.")
        return errors

    def validate_or_raise(self) -> None:
        """Validate configuration settings and raise ConfigError if any setting is invalid."""
        errors = self.validate()
        if errors:
            msg = "Invalid Kronagent configuration:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ConfigError(msg)

