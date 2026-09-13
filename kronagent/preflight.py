"""
Pre-flight readiness checks — what breaks *before* it touches production.

Kronagent's safety case is that nothing executes unattended until a human
decided it should. That case has a hole this module closes: the platform will
happily start with `KRONAGENT_DRY_RUN=false` and no quarantine security group
configured. In dry-run the missing value is harmless — it renders into the
planned API call as the literal string `<KRONAGENT_QUARANTINE_SG_ID unset>` and
is never sent. Turn dry-run off and that same action reaches AWS malformed.
Nothing warned anyone, because nothing was looking.

So this is a deliberately boring, deterministic audit of the deployment's own
configuration, run before the first finding arrives:

    python3 run_preflight.py            # human-readable report
    python3 run_preflight.py --json     # for CI / a deploy gate

Exit codes are the interface: 0 ready, 1 warnings worth reading, 2 something
that must be fixed before this is pointed at production. That makes it usable
as a container start gate or a CI step, not just something an operator reads.

The severity rule throughout: **a check only FAILs when the platform is armed
to act.** In dry-run a missing quarantine group is a warning about the future;
with dry-run off it is a defect that will surface as a failed containment in
the middle of an incident, which is the worst possible moment to discover it.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from typing import Literal, Optional

from .allowlist import AllowlistStore
from .audit import AuditLog
from .config import Settings
from .identity import DEFAULT_TENANT, owner_vacancy_checker, registry_configured
from .policy import _ACTION_PROPERTIES
from .schemas import ActionClass

Status = Literal["pass", "warn", "fail"]

# Settings an action class cannot execute without, and the provider it belongs
# to. These are the values that render as `<... unset>` placeholders in a
# planned call — fine on paper, wrong on the wire.
_REQUIRED_SETTINGS: dict[ActionClass, tuple[str, tuple[str, ...]]] = {
    ActionClass.ISOLATE_INSTANCE_SG: ("aws", ("quarantine_security_group_id",)),
    ActionClass.BLOCK_IP: ("aws", ("quarantine_nacl_id",)),
    ActionClass.ISOLATE_VM_NSG: ("azure", ("azure_quarantine_nsg_id",)),
    ActionClass.DEALLOCATE_VM: ("azure", ("azure_subscription_id",)),
    ActionClass.DISABLE_ENTRA_PRINCIPAL: ("azure", ("azure_subscription_id",)),
    ActionClass.ISOLATE_HOST_NETWORK: ("onprem", ("onprem_control_plane_url",
                                                 "onprem_quarantine_vlan")),
    ActionClass.DISABLE_LOCAL_ACCOUNT: ("onprem", ("onprem_control_plane_url",)),
    ActionClass.KILL_PROCESS: ("onprem", ("onprem_control_plane_url",)),
}

# Any of these being set is taken as "this operator is using that provider".
_PROVIDER_SETTINGS: dict[str, tuple[str, ...]] = {
    "aws": ("quarantine_security_group_id", "quarantine_nacl_id", "sqs_endpoint_url"),
    "azure": ("azure_subscription_id", "azure_quarantine_nsg_id"),
    "onprem": ("onprem_control_plane_url", "onprem_quarantine_vlan"),
    "kubernetes": ("kubeconfig_path", "kube_context"),
}

# The env var an operator actually sets, for settings whose name differs.
_ENV_NAMES: dict[str, str] = {
    "quarantine_security_group_id": "KRONAGENT_QUARANTINE_SG_ID",
    "quarantine_nacl_id": "KRONAGENT_QUARANTINE_NACL_ID",
    "azure_quarantine_nsg_id": "KRONAGENT_AZURE_QUARANTINE_NSG_ID",
    "azure_subscription_id": "KRONAGENT_AZURE_SUBSCRIPTION_ID",
    "onprem_control_plane_url": "KRONAGENT_ONPREM_CONTROL_PLANE_URL",
    "onprem_quarantine_vlan": "KRONAGENT_ONPREM_QUARANTINE_VLAN",
}

# Optional SDKs, by the settings that imply a provider is in use.
_PROVIDER_SDKS: tuple[tuple[str, str, str], ...] = (
    ("aws", "boto3", "pip install 'kronagent[aws]'"),
    ("kubernetes", "kubernetes", "pip install 'kronagent[k8s]'"),
    ("azure", "azure.identity", "pip install 'kronagent[azure]'"),
    ("gcp", "google.cloud.compute_v1", "pip install 'kronagent[gcp]'"),
)


@dataclass
class Check:
    """One finding about the deployment itself."""

    name: str
    status: Status
    detail: str
    fix: str = ""
    section: str = "general"

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "fix": self.fix, "section": self.section}


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == "fail"]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == "warn"]

    @property
    def exit_code(self) -> int:
        """0 ready · 1 warnings · 2 blocking. Usable as a deploy gate."""
        if self.failures:
            return 2
        return 1 if self.warnings else 0

    def as_dict(self) -> dict:
        return {
            "ready": not self.failures,
            "exit_code": self.exit_code,
            "counts": {
                "pass": len([c for c in self.checks if c.status == "pass"]),
                "warn": len(self.warnings),
                "fail": len(self.failures),
            },
            "checks": [c.as_dict() for c in self.checks],
        }


def _module_available(dotted: str) -> bool:
    try:
        return importlib.util.find_spec(dotted) is not None
    except (ImportError, ValueError):
        return False


def _writable(path: str) -> tuple[bool, str]:
    """Can this process actually write here? Checked now rather than at the
    first audit record, because the first audit record is written while
    responding to an incident."""
    if not path:
        return True, "not configured"
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if os.path.exists(path):
        return (os.access(path, os.W_OK), "exists")
    if not os.path.isdir(directory):
        return False, f"directory {directory} does not exist"
    return (os.access(directory, os.W_OK), f"will be created in {directory}")


# --------------------------------------------------------------------------- #
# Individual sections
# --------------------------------------------------------------------------- #

def _check_safety_posture(settings: Settings) -> list[Check]:
    checks: list[Check] = []
    if settings.dry_run:
        checks.append(Check(
            "dry_run", "pass",
            "ON — actions are planned and audited but never executed.",
            section="safety",
        ))
    else:
        # Not a failure: running live is the point, eventually. It is stated
        # loudly because every check below is graded against it.
        checks.append(Check(
            "dry_run", "warn",
            "OFF — containment will really execute against your infrastructure.",
            fix="Set KRONAGENT_DRY_RUN=true to plan without executing.",
            section="safety",
        ))

    if settings.kill_switch:
        checks.append(Check(
            "kill_switch", "warn",
            "ENGAGED — every containment action is blocked, including approved ones.",
            fix="Set KRONAGENT_KILL_SWITCH=false when you intend to respond again.",
            section="safety",
        ))
    else:
        checks.append(Check("kill_switch", "pass", "OFF — containment is permitted.",
                            section="safety"))

    if settings.min_severity_for_containment <= 0:
        checks.append(Check(
            "min_severity", "warn",
            f"Threshold is {settings.min_severity_for_containment} — every finding, "
            f"however trivial, is eligible for containment.",
            fix="Set KRONAGENT_MIN_SEVERITY to a positive value (default 4.0).",
            section="safety",
        ))
    else:
        checks.append(Check(
            "min_severity", "pass",
            f"Findings below severity {settings.min_severity_for_containment} are alert-only.",
            section="safety",
        ))
    return checks


def _provider_in_use(settings: Settings, provider: str) -> bool:
    return any(getattr(settings, s, "") for s in _PROVIDER_SETTINGS.get(provider, ()))


def _check_execution_readiness(settings: Settings, store: AllowlistStore) -> list[Check]:
    """The check this module exists for: can the actions this deployment is
    allowed to take actually be carried out?

    Only for action classes this deployment can plausibly reach — one it has
    allowlisted, or one whose provider it has started configuring. Reporting
    on-prem gaps to a pure-AWS deployment would bury the one line that matters
    under seven that don't, which is how a report gets ignored.
    """
    checks: list[Check] = []
    allowlisted = {e.action_class for e in store.active()}

    for action_class, (provider, required) in sorted(
        _REQUIRED_SETTINGS.items(), key=lambda kv: kv[0].value
    ):
        missing = [s for s in required if not getattr(settings, s, "")]
        if not missing:
            continue
        on_allowlist = action_class.value in allowlisted
        if not on_allowlist and not _provider_in_use(settings, provider):
            continue  # not reachable here — don't spend the operator's attention
        env = ", ".join(_ENV_NAMES.get(s, s.upper()) for s in missing)

        if settings.dry_run:
            # Nothing can go wrong today; say what would go wrong tomorrow.
            status: Status = "warn"
            detail = (f"{action_class.value} has no {env} configured. Harmless in dry-run — "
                      f"the value renders as a placeholder in the planned call — but this "
                      f"action cannot execute for real until it is set.")
        else:
            status = "fail"
            reach = ("It is on the auto-execute allowlist, so it can fire unattended."
                     if on_allowlist else
                     "It is approval-gated, but an approved action executes the same way.")
            detail = (f"{action_class.value} has no {env} configured and dry-run is OFF. "
                      f"{reach} The call would go out malformed.")
        checks.append(Check(
            f"config:{action_class.value}", status, detail,
            fix=f"Set {env}, or demote {action_class.value} so it cannot be selected.",
            section="execution",
        ))

    if not checks:
        checks.append(Check(
            "execution_config", "pass",
            "Every action class this deployment can reach has the configuration it "
            "needs to actually execute.",
            section="execution",
        ))
    return checks


def _check_providers(settings: Settings) -> list[Check]:
    """An adapter whose SDK is missing plans fine and fails at execution."""
    in_use = {
        "aws": bool(settings.quarantine_security_group_id or settings.quarantine_nacl_id
                    or settings.sqs_endpoint_url or os.getenv("KRONAGENT_SQS_QUEUE_URL")),
        "kubernetes": bool(settings.kubeconfig_path or settings.kube_context),
        "azure": bool(settings.azure_subscription_id or settings.azure_quarantine_nsg_id),
        "gcp": False,
    }
    checks: list[Check] = []
    for provider, module, install in _PROVIDER_SDKS:
        if not in_use.get(provider):
            continue
        if _module_available(module):
            checks.append(Check(f"sdk:{provider}", "pass", f"{module} is importable.",
                                section="providers"))
        else:
            checks.append(Check(
                f"sdk:{provider}", "fail" if not settings.dry_run else "warn",
                f"{provider} looks configured but {module} is not installed — planning "
                f"works, execution raises at the moment of containment.",
                fix=install, section="providers",
            ))
    if not checks:
        checks.append(Check(
            "providers", "pass",
            "No cloud provider configured — file replay and dry-run only.",
            section="providers",
        ))
    return checks


def _check_storage(settings: Settings) -> list[Check]:
    checks: list[Check] = []
    for label, path in (
        ("audit log", settings.audit_log_path),
        ("approval store", settings.approval_store_path),
        ("allowlist store", settings.allowlist_store_path),
    ):
        ok, why = _writable(path)
        if ok:
            checks.append(Check(f"writable:{label}", "pass", f"{path} — {why}.",
                                section="storage"))
        else:
            checks.append(Check(
                f"writable:{label}", "fail",
                f"{path} is not writable ({why}).",
                fix="Fix the path or its permissions — an unwritable audit log means "
                    "actions run with no record.",
                section="storage",
            ))

    verified, broken_line = AuditLog.verify(settings.audit_log_path)
    if verified:
        checks.append(Check("audit chain", "pass",
                            "Hash chain verifies end to end.", section="storage"))
    else:
        checks.append(Check(
            "audit chain", "fail",
            f"Hash chain is broken at line {broken_line} — a past record was altered "
            f"or truncated.",
            fix="Preserve the file for forensics and investigate before running further.",
            section="storage",
        ))
    return checks


def _check_identity(settings: Settings) -> list[Check]:
    checks: list[Check] = []
    if registry_configured(settings.operator_registry_path):
        checks.append(Check(
            "operator registry", "pass",
            f"{settings.operator_registry_path} — approvals and promotions are "
            f"authenticated and non-repudiable.",
            section="identity",
        ))
    else:
        checks.append(Check(
            "operator registry", "warn",
            "Not configured — unauthenticated mode. Anyone who can run the CLI can "
            "approve actions and promote classes, with a free-text --by recorded as "
            "identity_verified=false.",
            fix="Create one with operators.py and set KRONAGENT_OPERATOR_REGISTRY.",
            section="identity",
        ))

    if bool(settings.oidc_issuer) != bool(settings.oidc_audience):
        checks.append(Check(
            "oidc", "fail",
            "Half-configured: OIDC needs both an issuer and an audience, and enforces "
            "neither with only one set.",
            fix="Set KRONAGENT_OIDC_ISSUER and KRONAGENT_OIDC_AUDIENCE, or clear both.",
            section="identity",
        ))
    elif settings.oidc_issuer and not settings.oidc_verify_signature:
        checks.append(Check(
            "oidc", "fail",
            "Signature verification is DISABLED — any self-signed token is accepted as "
            "a valid operator identity.",
            fix="Set KRONAGENT_OIDC_VERIFY_SIGNATURE=true.",
            section="identity",
        ))
    elif settings.oidc_issuer:
        checks.append(Check("oidc", "pass", f"Enforced against {settings.oidc_issuer}.",
                            section="identity"))
    return checks


def _check_governance(settings: Settings, store: AllowlistStore) -> list[Check]:
    checks: list[Check] = []
    entries = store.list()
    active = store.active()

    if not entries:
        checks.append(Check(
            "allowlist", "pass",
            "Empty — every containment action requires human approval.",
            section="governance",
        ))
        return checks

    unknown = [e.action_class for e in entries
               if e.action_class not in {ac.value for ac in ActionClass}]
    if unknown:
        checks.append(Check(
            "allowlist:unknown", "warn",
            f"{', '.join(unknown)} name action classes that no longer exist. They grant "
            f"nothing, but they are clutter in a governance record.",
            fix="Remove them with promote.py remove.",
            section="governance",
        ))

    expired = [e.action_class for e in store.expired()]
    if expired:
        checks.append(Check(
            "allowlist:expired", "warn",
            f"{', '.join(expired)} have lapsed and no longer grant autonomy.",
            fix="Renew with promote.py add --expires-in, or drop with promote.py remove.",
            section="governance",
        ))

    suspended = [e for e in entries if e.is_suspended and not e.is_expired()]
    if suspended:
        checks.append(Check(
            "allowlist:suspended", "warn",
            "; ".join(f"{e.action_class} ({e.suspended_reason})" for e in suspended)
            + " — suspended, no longer granting autonomy.",
            fix="Renew with promote.py add --owner <someone in standing>, reassign with "
                "promote.py reassign --to, or drop with promote.py remove.",
            section="governance",
        ))

    owner_check = owner_vacancy_checker(settings.operator_registry_path, DEFAULT_TENANT)
    vacant: dict[str, str] = {}
    if owner_check is None:
        if active:
            checks.append(Check(
                "allowlist:owners", "warn",
                "Owner standing is not checked — there is no operator registry, so nothing "
                "notices when an entry's owner leaves. (OIDC alone cannot answer this: it "
                "only knows people while they are signing in.)",
                fix="Configure KRONAGENT_OPERATOR_REGISTRY listing every entry owner.",
                section="governance",
            ))
    else:
        for e in active:
            vacancy = owner_check(e.owner)
            if vacancy is not None:
                vacant[e.action_class] = vacancy.reason
        if vacant:
            checks.append(Check(
                "allowlist:owners", "fail",
                "; ".join(f"{ac}: {why}" for ac, why in sorted(vacant.items()))
                + " — refused at the gate, and suspended on the next pipeline run.",
                fix="Hand each to an owner in standing with promote.py reassign --to, or "
                    "drop it with promote.py remove.",
                section="governance",
            ))

    no_ttl = [e.action_class for e in active if not e.expires_at]
    if no_ttl:
        checks.append(Check(
            "allowlist:no_ttl", "warn",
            f"{', '.join(no_ttl)} have no expiry — standing authority nobody will be "
            f"asked to re-confirm.",
            fix="Re-promote with --expires-in 90d so the decision has to be re-made.",
            section="governance",
        ))

    # The headline number: what can actually run unattended right now.
    autonomous = sorted(
        e.action_class for e in active
        if e.action_class in {ac.value for ac in ActionClass}
        and e.action_class not in vacant
        and _ACTION_PROPERTIES.get(ActionClass(e.action_class), {}).get("destructive") is False
    )
    if autonomous and not settings.dry_run:
        checks.append(Check(
            "autonomy", "warn",
            f"{len(autonomous)} action class(es) can execute unattended against production: "
            f"{', '.join(autonomous)}.",
            section="governance",
        ))
    elif autonomous:
        checks.append(Check(
            "autonomy", "pass",
            f"{len(autonomous)} class(es) allowlisted, but dry-run is on so nothing executes: "
            f"{', '.join(autonomous)}.",
            section="governance",
        ))
    return checks


def _check_agents(settings: Settings) -> list[Check]:
    checks: list[Check] = []
    if os.getenv("GEMINI_API_KEY"):
        checks.append(Check("llm", "pass",
                            "GEMINI_API_KEY set — triage, intel, correlation and command "
                            "enrichment are available.",
                            section="agents"))
    else:
        checks.append(Check(
            "llm", "warn",
            "GEMINI_API_KEY not set — the pipeline degrades to deterministic triage. "
            "Detection and containment still work; the narrative context does not.",
            fix="Set GEMINI_API_KEY, or accept deterministic-only triage.",
            section="agents",
        ))

    if settings.trajectory_guard_enabled:
        checks.append(Check(
            "trajectory guard", "pass",
            f"Armed — halts after {settings.trajectory_max_auto_executions} autonomous "
            f"executions in {settings.trajectory_window_seconds:.0f}s, or "
            f"{settings.trajectory_max_scope_violations} out-of-scope targets.",
            section="agents",
        ))
    else:
        checks.append(Check(
            "trajectory guard", "warn" if settings.dry_run else "fail",
            "DISABLED — nothing bounds a runaway burst of autonomous actions or an "
            "action redirected onto a resource its finding never implicated.",
            fix="Set KRONAGENT_TRAJECTORY_GUARD=true.",
            section="agents",
        ))

    if settings.trajectory_state_path and os.path.exists(settings.trajectory_state_path):
        checks.append(Check(
            "trajectory halt", "warn",
            f"A halt is latched in {settings.trajectory_state_path} — containment is "
            f"stopped until it is cleared.",
            fix="Inspect with halt.py status, clear with halt.py clear once understood.",
            section="agents",
        ))
    return checks


def run_preflight(settings: Optional[Settings] = None) -> PreflightReport:
    """Audit a deployment's configuration. Pure reads — nothing is created,
    written or sent, so it is safe to run against production at any time."""
    settings = settings or Settings.from_env()
    store = AllowlistStore(settings.allowlist_store_path)

    report = PreflightReport()
    report.checks.extend(_check_safety_posture(settings))
    report.checks.extend(_check_execution_readiness(settings, store))
    report.checks.extend(_check_providers(settings))
    report.checks.extend(_check_storage(settings))
    report.checks.extend(_check_identity(settings))
    report.checks.extend(_check_governance(settings, store))
    report.checks.extend(_check_agents(settings))
    return report
