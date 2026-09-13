"""
Orchestrator: wire ingestion -> triage -> policy -> containment -> audit.

Each finding flows through sequentially and deterministically. Every stage
writes an immutable audit record before the next runs, so the log is a complete
decision trail even if a later stage fails. Containment is gated by the policy
engine and the global dry_run / kill_switch controls.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .allowlist import AllowlistStore
from .approvals import ApprovalRequest, ApprovalStore
from .audit import AuditLog
from .commander import IncidentAssessment, IncidentCommanderAgent
from .config import Settings
from .containment import ContainmentExecutor
from .correlation import CorrelationAgent, CorrelationAssessment, CorrelationMemory
from .forensics import ForensicsAgent, ForensicsResult
from .identity import owner_vacancy_checker
from .ingestion import QueuedFinding
from .intel import ThreatIntelAgent, ThreatIntelAssessment
from .model import Finding
from .policy import PolicyEngine
from .schemas import AuditRecord
from .trajectory import TrajectoryGuard
from .triage import TriageEngine


import os


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def _log(stage: str, msg: str) -> None:
    print(f"{_ts()} [{stage}] {msg}", flush=True)


def get_tenant_path(base_path: str, tenant_id: str) -> str:
    if not base_path:
        return ""
    if not tenant_id or tenant_id == "default":
        return base_path
    root, ext = os.path.splitext(base_path)
    return f"{root}_{tenant_id}{ext}"


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        *,
        triage: TriageEngine,
        policy: PolicyEngine,
        containment: ContainmentExecutor,
        audit: AuditLog,
        approvals: ApprovalStore | None = None,
        threat_intel: ThreatIntelAgent | None = None,
        correlation: CorrelationAgent | None = None,
        commander: IncidentCommanderAgent | None = None,
        forensics: ForensicsAgent | None = None,
        trajectory: TrajectoryGuard | None = None,
    ) -> None:
        self._settings = settings
        self._triage = triage
        self._policy = policy
        self._containment = containment
        self._audit = audit
        self._approvals = approvals
        self._threat_intel = threat_intel
        self._correlation = correlation
        self._commander = commander
        self._forensics = forensics
        # Behavioral-trajectory guard: the automatic kill switch over Kronagent's own
        # action stream. Session-scoped and shared across tenants/workers — a
        # runaway is a property of this Kronagent process, not of one tenant.
        self._trajectory = trajectory
        # Session-scoped campaign memory cache per tenant
        self._tenant_memories: dict[str, CorrelationMemory] = {}
        # Session-scoped campaign memory: only maintained when a correlation
        # agent is present. Every finding is recorded (incl. non-actionable
        # noise, which is often a campaign's first stage).
        self._memory = CorrelationMemory(settings.db_path) if correlation is not None else None
        self._processed = 0

    @property
    def processed(self) -> int:
        return self._processed

    async def _handle(self, finding: Finding) -> None:
        _log("INCIDENT", f"--- [{finding.provider}] {finding.finding_id} | "
                         f"{finding.finding_type} | severity={finding.severity} | tenant={finding.tenant_id} ---")

        # Dynamically resolve tenant-specific stores
        if not finding.tenant_id or finding.tenant_id == "default":
            tenant_audit = self._audit
            tenant_allowlist = self._policy._allowlist if hasattr(self._policy, "_allowlist") else AllowlistStore(self._settings.allowlist_store_path)
            tenant_approvals = self._approvals
            tenant_memory = self._memory
        else:
            tenant_audit_path = get_tenant_path(self._settings.audit_log_path, finding.tenant_id)
            audit_class = self._audit.__class__ if self._audit else AuditLog
            tenant_audit = audit_class(tenant_audit_path)

            tenant_allowlist_path = get_tenant_path(self._settings.allowlist_store_path, finding.tenant_id)
            allowlist_class = self._policy._allowlist.__class__ if hasattr(self._policy, "_allowlist") else AllowlistStore
            tenant_allowlist = allowlist_class(tenant_allowlist_path)

            tenant_approvals = None
            if self._approvals is not None:
                tenant_approvals_path = get_tenant_path(self._settings.approval_store_path, finding.tenant_id)
                approvals_class = self._approvals.__class__
                tenant_approvals = approvals_class(tenant_approvals_path)

            tenant_memory = None
            if self._correlation is not None:
                if finding.tenant_id not in self._tenant_memories:
                    tenant_db_path = get_tenant_path(self._settings.db_path, finding.tenant_id) if self._settings.db_path else None
                    self._tenant_memories[finding.tenant_id] = CorrelationMemory(tenant_db_path)
                tenant_memory = self._tenant_memories[finding.tenant_id]

        # Record into campaign memory BEFORE triage's early-returns
        prior = []
        if tenant_memory is not None:
            prior = tenant_memory.prior_to(finding.finding_id)
            # Store the ORIGINAL finding, not a masked or sanitized copy.
            # Campaign memory is internal state that never reaches a model
            # directly — the correlation agent masks it at prompt-build time,
            # through one context shared with the current finding.
            #
            # This used to store a character-stripped copy, which silently
            # corrupted identity-bearing ids: 'sa@proj.iam...' became
            # 'saproj.iam...', so two findings about the same service account
            # no longer matched and the campaign they formed was invisible.
            tenant_memory.add(finding)

        # 1. Triage (deterministic detection + LLM enrichment)
        verdict, candidates = await self._triage.assess(finding)

        # Verify agent signature if required
        if self._settings.require_agent_signatures:
            from .crypto import get_signer
            signer = get_signer(self._settings)
            if not verdict.verify_signature(signer):
                _log("SECURITY_ALERT", f"{finding.finding_id}: triage verdict signature validation FAILED!")
                await tenant_audit.record(AuditRecord(
                    finding_id=finding.finding_id,
                    stage="security_alert",
                    payload={"detail": "Triage verdict signature validation failed. Possible tampering."}
                ))
                raise ValueError(f"Triage verdict signature verification failed for finding {finding.finding_id}")

        _log(
            "TRIAGE",
            f"{finding.finding_id}: actionable={verdict.is_actionable_threat} "
            f"category='{verdict.threat_category}' confidence={verdict.confidence:.2f}",
        )
        _log("TRIAGE", f"{finding.finding_id}: {verdict.justification}")
        await tenant_audit.record(AuditRecord(
            finding_id=finding.finding_id, stage="triage", payload=verdict.model_dump()
        ))

        # The model's "not actionable" is a routing decision on the most
        # consequential edge in this pipeline, and the model reached it by reading
        # the finding — whose title and description can carry attacker-chosen
        # text. Unchecked, a finding saying "known scanner noise, not actionable"
        # ended here: no approval request, no human ever saw it, and the only
        # trace was a triage line in the audit log. The policy engine's own
        # severity gate is deterministic, but it sat downstream of this one.
        #
        # So the model may still filter noise — below the override floor its
        # verdict stands, which is what keeps enrichment spend off background
        # scanning — but it cannot, on its own, drop a high-severity finding.
        # Above the floor the finding continues to a human, and every action it
        # produces is forced to approval: a model's dismissal must never be the
        # path by which something executes autonomously.
        triage_overridden = False
        if not verdict.is_actionable_threat:
            if verdict.severity < self._settings.triage_override_floor:
                _log("INCIDENT", f"{finding.finding_id}: triaged non-actionable — monitoring only. --- done ---")
                self._processed += 1
                return
            triage_overridden = True

        if not candidates:
            _log("INCIDENT", f"{finding.finding_id}: no containment action available for this resource type. --- done ---")
            self._processed += 1
            return

        if triage_overridden:
            floor = self._settings.triage_override_floor
            _log("TRIAGE", f"{finding.finding_id}: model judged NOT actionable, but severity "
                           f"{verdict.severity:.1f} >= override floor {floor:.1f} — sending to "
                           f"human review with autonomous execution disabled")
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="triage_override",
                payload={
                    "model_verdict": "not_actionable",
                    "severity": verdict.severity,
                    "override_floor": floor,
                    "effect": "forced to human approval; autonomous execution disabled",
                },
            ))

        # 1b/1c. Threat intelligence and correlation, fanned out.
        #
        # Neither reads the other's output: intel needs only the finding, and
        # correlation needs the finding plus `prior`, which was snapshotted from
        # the tenant's memory before triage. Run one after the other they cost
        # two model round-trips of wall-clock per actionable finding; together,
        # one. The commander below is the join — it needs both.
        #
        # A TaskGroup rather than gather(): if one agent raises, gather() returns
        # the error while the other keeps running unattended, and nobody ever
        # collects its result. A TaskGroup cancels the sibling. Both real agents
        # already degrade to available=False instead of raising, so this path is
        # for anything that does not — and it unwraps the ExceptionGroup, so the
        # worker logs the agent's actual error rather than "unhandled errors in
        # a TaskGroup".
        #
        # Worth knowing: this doubles peak concurrent model calls, from
        # max_workers to 2 x max_workers. If a provider rate-limits, lower
        # KRONAGENT_MAX_WORKERS rather than removing the fan-out.
        async def _intel() -> ThreatIntelAssessment:
            if self._threat_intel is None:
                return ThreatIntelAssessment(finding_id=finding.finding_id, available=False)
            return await self._threat_intel.assess(finding)

        async def _correlate() -> CorrelationAssessment:
            if self._correlation is None:
                return CorrelationAssessment(finding_id=finding.finding_id, available=False)
            return await self._correlation.assess(finding, prior)

        try:
            async with asyncio.TaskGroup() as enrichment:
                intel_task = enrichment.create_task(_intel())
                correlation_task = enrichment.create_task(_correlate())
        except ExceptionGroup as group:
            raise group.exceptions[0] from None
        intel, correlation = intel_task.result(), correlation_task.result()

        # Recorded AFTER both finish and always in this order, never in whichever
        # order the models happened to answer. The audit log is a hash chain, and
        # a chain whose record order depends on provider latency is one that two
        # identical runs cannot reproduce.
        if self._threat_intel is not None:
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="threat_intel", payload=intel.model_dump()
            ))
            if intel.available:
                techniques = ", ".join(
                    f"{t.technique_id} ({t.tactic})" for t in intel.mitre_techniques if t.technique_id
                ) or "none mapped"
                _log("INTEL", f"{finding.finding_id}: ATT&CK: {techniques} | stage: "
                              f"{intel.attack_lifecycle_stage or 'n/a'}")
                _log("INTEL", f"{finding.finding_id}: {intel.intel_summary}")

        if self._correlation is not None:
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="correlation", payload=correlation.model_dump()
            ))
            if correlation.available and correlation.part_of_campaign:
                _log("CORRELATE", f"{finding.finding_id}: CAMPAIGN — related to "
                                  f"{correlation.related_finding_ids}")
                _log("CORRELATE", f"{finding.finding_id}: {correlation.correlation_summary}")
            elif correlation.available:
                _log("CORRELATE", f"{finding.finding_id}: no campaign link found "
                                  f"across {len(prior)} prior finding(s)")

        # 1d. Incident Commander (advisory synthesis)
        command = IncidentAssessment(finding_id=finding.finding_id, available=False)
        if self._commander is not None:
            command = await self._commander.assess(finding, verdict, intel, correlation)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="command", payload=command.model_dump()
            ))
            if command.available:
                flag = "⚠ ESCALATE NOW" if command.escalate_to_human_now else "queued"
                _log("COMMAND", f"{finding.finding_id}: priority={command.priority or 'n/a'} "
                                f"[{flag}] — {command.escalation_reason}")
                _log("COMMAND", f"{finding.finding_id}: {command.incident_narrative}")

        # 1e. Forensics (deterministic)
        forensics = ForensicsResult(finding_id=finding.finding_id, provider=finding.provider)
        if self._forensics is not None:
            forensics = await self._forensics.collect(finding, tenant_audit)
            if forensics.items:
                _log("FORENSICS", f"{finding.finding_id}: preserved {len(forensics.items)} "
                                  f"evidence item(s): {forensics.evidence_kinds()}")
                for it in forensics.items:
                    _log("FORENSICS", f"{finding.finding_id}:   {it.kind} custody={it.custody_sha256[:12]}…")

        # 1f. Sweep lapsed allowlist TTLs before any policy decision, so the
        # audit chain records the expiry ahead of the first decision that
        # reflects it. The gate itself doesn't depend on this — is_allowed()
        # already refuses an expired entry — so a store without the sweep
        # (an older double in a test) is still safe, just less legible.
        if hasattr(tenant_allowlist, "expire_due"):
            for lapsed in await tenant_allowlist.expire_due(audit=tenant_audit):
                _log("GOVERNANCE", f"{lapsed.action_class}: allowlist entry EXPIRED "
                                   f"(promoted by {lapsed.promoted_by} at {lapsed.promoted_at}, "
                                   f"owner {lapsed.owner}) — "
                                   f"this class requires human approval again until renewed")
        # Same shape for an owner who has left: the gate already refuses the
        # entry, and this latches the suspension into the audit chain first.
        if hasattr(tenant_allowlist, "suspend_vacant_owners"):
            owner_check = owner_vacancy_checker(self._settings.operator_registry_path,
                                                finding.tenant_id)
            for entry, vacancy in await tenant_allowlist.suspend_vacant_owners(
                    audit=tenant_audit, owner_check=owner_check):
                _log("GOVERNANCE", f"{entry.action_class}: allowlist entry SUSPENDED — "
                                   f"{vacancy.reason}; this class requires human approval "
                                   f"until an operator renews it or reassigns it to an owner "
                                   f"in standing")

        # 2 + 3. Policy decision and containment, per candidate action.
        guard = self._trajectory
        for action in candidates:
            # 2a. Behavioral-trajectory guard — the automatic kill switch over
            # Kronagent's OWN action stream, applied BEFORE the policy engine so a
            # redirected or runaway action never reaches execution or the
            # approval queue. Deterministic, so it cannot itself be injected.
            if guard is not None:
                if guard.halted:
                    await tenant_audit.record(AuditRecord(
                        finding_id=finding.finding_id, stage="trajectory_halt",
                        payload={"blocked_action": action.model_dump(),
                                 "halt_reason": guard.halt_reason},
                    ))
                    _log("TRAJECTORY", f"{finding.finding_id}: {action.action_class.value} BLOCKED — "
                                       f"automatic kill switch engaged: {guard.halt_reason}")
                    continue
                scope_event = guard.check_scope(action, finding)
                if scope_event is not None:
                    await tenant_audit.record(AuditRecord(
                        finding_id=finding.finding_id, stage="trajectory_scope_violation",
                        payload=scope_event.model_dump(),
                    ))
                    _log("TRAJECTORY", f"{finding.finding_id}: {action.action_class.value} BLOCKED "
                                       f"(out of scope) target={action.target} — {scope_event.reason}")
                    if scope_event.halted:
                        _log("TRAJECTORY", f"{finding.finding_id}: automatic kill switch ENGAGED — "
                                           f"{guard.halt_reason}")
                    continue

            import inspect
            sig = inspect.signature(self._policy.decide)
            if "allowlist" in sig.parameters:
                decision = self._policy.decide(action, severity=verdict.severity, allowlist=tenant_allowlist)
            else:
                decision = self._policy.decide(action, severity=verdict.severity)

            if triage_overridden and decision.disposition in ("auto_execute", "requires_approval"):
                # Kronagent's words only. The model's justification is already in
                # the triage audit record, and copying model prose into
                # policy_reason would put steerable text in a field reviewers are
                # told Kronagent computed.
                decision = decision.model_copy(update={
                    "disposition": "requires_approval",
                    "reason": (
                        f"triage model judged this finding NOT actionable, but its "
                        f"severity {verdict.severity:.1f} is at or above the override "
                        f"floor {self._settings.triage_override_floor:.1f}, so a human "
                        f"decides and autonomous execution is disabled. Policy: "
                        f"{decision.reason}"
                    ),
                })
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="policy",
                payload={"action": action.model_dump(), "decision": decision.model_dump()},
            ))

            # 2b. Runaway-rate limit: count actions the pipeline is about to
            # execute autonomously. Crossing the window ceiling latches the halt
            # and blocks the very action that crossed it (fail safe — the
            # runaway action does not slip through before the switch trips).
            if guard is not None and decision.disposition == "auto_execute":
                halt_event = guard.note_auto_execution(action, finding)
                if halt_event is not None:
                    await tenant_audit.record(AuditRecord(
                        finding_id=finding.finding_id, stage="trajectory_halt",
                        payload=halt_event.model_dump(),
                    ))
                    _log("TRAJECTORY", f"{finding.finding_id}: {action.action_class.value} BLOCKED — "
                                       f"automatic kill switch ENGAGED: {guard.halt_reason}")
                    continue

            outcome = await self._containment.execute(action, decision)
            await tenant_audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="containment", payload=outcome.model_dump(),
            ))

            # An allowlist entry only earns its keep when it authorizes
            # something. Recorded on the attempt, not on success: the standing
            # authority was exercised either way, and it's the exercising that
            # review cares about. Approval-gated executions deliberately don't
            # count — those were authorized by a human, not by the entry.
            if decision.disposition == "auto_execute" and hasattr(tenant_allowlist, "record_fired"):
                tenant_allowlist.record_fired(action.action_class)

            marker = {
                "auto_execute": "AUTO",
                "requires_approval": "APPROVAL",
                "blocked": "BLOCKED",
            }[decision.disposition]
            _log(
                "POLICY",
                f"{finding.finding_id}: {action.action_class.value} -> {marker} "
                f"(reversible={decision.reversible}, blast={decision.blast_radius.value})",
            )

            # Persist approval-gated actions so an operator can authorize them.
            if decision.disposition == "requires_approval" and tenant_approvals is not None:
                req = tenant_approvals.add(ApprovalRequest(
                    finding_id=finding.finding_id,
                    finding_type=finding.finding_type,
                    severity=verdict.severity,
                    provider=action.provider,
                    action_class=action.action_class,
                    target=action.target,
                    rationale=action.rationale,
                    parameters=action.parameters,
                    policy_reason=decision.reason,
                    reversible=decision.reversible,
                    blast_radius=decision.blast_radius.value,
                    planned_api_calls=outcome.api_calls,
                    rollback_hint=outcome.rollback_hint,
                    mitre_techniques=intel.technique_ids(),
                    threat_intel_summary=intel.intel_summary,
                    related_finding_ids=correlation.related_finding_ids,
                    correlation_summary=correlation.correlation_summary,
                    incident_priority=command.priority,
                    escalated=command.escalate_to_human_now,
                    incident_narrative=command.incident_narrative,
                    evidence_collected=forensics.evidence_kinds(),
                ))
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}  [approval id: {req.request_id}]")
                
                # Trigger interactive Slack notification card in a background thread executor
                from .chatops import ChatOpsNotifier
                
                ts = await asyncio.to_thread(
                    ChatOpsNotifier.send_approval_notification,
                    self._settings,
                    req
                )
                if ts:
                    req.slack_ts = ts
                    tenant_approvals.update(req)
            else:
                _log("CONTAIN", f"{finding.finding_id}: {outcome.detail}")

            for call in outcome.api_calls:
                _log("CONTAIN", f"{finding.finding_id}:   plan $ {call}")
            _log("CONTAIN", f"{finding.finding_id}:   rollback: {outcome.rollback_hint}")

        _log("INCIDENT", f"{finding.finding_id}: --- response complete ---")
        self._processed += 1

    async def _worker(self, queue: "asyncio.Queue[QueuedFinding]", ingestion_done: asyncio.Event) -> None:
        while not (ingestion_done.is_set() and queue.empty()):
            try:
                item = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            finding = item.finding
            try:
                await self._handle(finding)
            except Exception as exc:  # noqa: BLE001 - one bad finding must not stop the pipeline
                _log("ERROR", f"{finding.finding_id}: pipeline error — {type(exc).__name__}: {exc}")
                if not finding.tenant_id or finding.tenant_id == "default":
                    tenant_audit = self._audit
                else:
                    tenant_audit_path = get_tenant_path(self._settings.audit_log_path, finding.tenant_id)
                    audit_class = self._audit.__class__ if self._audit else AuditLog
                    tenant_audit = audit_class(tenant_audit_path)
                await tenant_audit.record(AuditRecord(
                    finding_id=finding.finding_id, stage="error", payload={"error": str(exc)}
                ))
            finally:
                # Retire the message from the upstream source only after it has
                # been fully processed and audited (at-least-once). A failed ack
                # is logged, not raised — the message will simply redeliver.
                try:
                    await item.ack()
                except Exception as exc:  # noqa: BLE001
                    _log("ERROR", f"{finding.finding_id}: ack failed (will redeliver) — "
                                  f"{type(exc).__name__}: {exc}")
                queue.task_done()

    async def run(self, queue: "asyncio.Queue[QueuedFinding]", ingestion_done: asyncio.Event) -> None:
        max_workers = getattr(self._settings, "max_workers", 1)
        if max_workers <= 1:
            await self._worker(queue, ingestion_done)
        else:
            _log("ORCHESTRATOR", f"Starting parallel execution with {max_workers} worker tasks")
            workers = [
                asyncio.create_task(self._worker(queue, ingestion_done))
                for _ in range(max_workers)
            ]
            await asyncio.gather(*workers)
