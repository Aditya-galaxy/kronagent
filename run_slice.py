#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — AWS GuardDuty threat-defense vertical slice (runnable entry point).

Wires the real pipeline end to end:

    GuardDuty findings  ->  Triage (deterministic + LLM)  ->  Policy (graduated
    autonomy)  ->  Containment (dry-run by default)  ->  hash-chained audit log

Ingestion defaults to replaying real-schema findings from samples/ so the whole
system runs locally with no AWS account. Point it at a live SQS queue (fed by
GuardDuty -> EventBridge) and flip KRONAGENT_DRY_RUN=false + promote an action
class with promote.py to graduate it toward autonomy.

Safety posture (all overridable via env, all default safe):
    KRONAGENT_DRY_RUN=true                 # plan only; nothing is executed
    KRONAGENT_KILL_SWITCH=false            # global halt of all containment
    KRONAGENT_MIN_SEVERITY=4.0             # below this: alert only
    KRONAGENT_QUARANTINE_SG_ID=            # required for real instance isolation
    GEMINI_API_KEY=...                 # triage enrichment (optional; degrades)

The auto-execute allowlist is NOT an env var — it's an audited, persisted
store. Empty until an operator runs `promote.py add <action_class>`. See
allowlist.py.

Usage:
    python3 run_slice.py [path-to-findings.json]
"""

from __future__ import annotations

import asyncio
import os
import sys

from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.commander import IncidentCommanderAgent
from kronagent.containment import ContainmentExecutor
from kronagent.correlation import CorrelationAgent
from kronagent.forensics import ForensicsAgent
from kronagent.connect import ConnectionState, ConnectionStore, CredentialBroker, Grant
from kronagent.ingestion import (
    FileReplaySource,
    GuardDutyPollingSource,
    QueuedFinding,
    SqsFindingSource,
)
from kronagent.intel import ThreatIntelAgent
from kronagent.llm import GeminiTriageClient, LLMUnavailableError
from kronagent.orchestrator import Orchestrator, _log
from kronagent.policy import PolicyEngine
from kronagent.providers import NORMALIZERS, build_containment_adapters
from kronagent.triage import TriageEngine

# Default file-replay set — one sample per provider, to exercise the whole
# multi-provider pipeline in one local run with no cloud/cluster.
_DEFAULT_REPLAY: list[tuple[str, str]] = [
    ("aws", "samples/guardduty_findings.json"),
    ("kubernetes", "samples/k8s_audit_events.json"),
]


async def _stream_all(sources, queue, stop) -> None:
    """Run several live sources concurrently onto the shared queue.

    One source per connected tenant. gather() so a single tenant's transient
    failure cannot stall the others — each source already backs off internally.
    """
    await asyncio.gather(*(s.stream(queue, stop) for s in sources))


async def _replay_files(sources, queue, stop) -> None:
    """Stream several file sources into the queue in order, then return."""
    for provider, path in sources:
        normalizer = NORMALIZERS[provider]
        await FileReplaySource(path, normalizer, interval=0.5).stream(queue, stop)
        if stop.is_set():
            return


async def main(replay: list[tuple[str, str]]) -> int:
    settings = Settings.from_env()

    # Triage LLM is optional — the pipeline degrades to deterministic triage.
    try:
        llm: GeminiTriageClient | None = GeminiTriageClient()
        llm_status = "Gemini triage enabled"
    except LLMUnavailableError as exc:
        llm = None
        llm_status = f"LLM disabled ({exc}) — deterministic triage only"

    audit = AuditLog(settings.audit_log_path)
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=settings.auto_execute_allowlist)
    from kronagent.crypto import get_signer
    signer = get_signer(settings)
    triage = TriageEngine(llm, signer)
    threat_intel = ThreatIntelAgent(llm)  # same LLM client; degrades if unavailable
    correlation = CorrelationAgent(llm)   # campaign correlation across the finding window
    commander = IncidentCommanderAgent(llm)  # synthesis + escalation (advisory)
    forensics = ForensicsAgent(settings)     # deterministic evidence + chain of custody
    policy = PolicyEngine(settings, allowlist)
    # Containment runs inside the CUSTOMER's account, under the role they
    # granted and can revoke — not against our ambient process credentials.
    # The seam and the broker both already existed; only this wiring was
    # missing, which meant every AWS action would have run against whatever
    # credentials the process happened to hold.
    connection_store = ConnectionStore(settings.connection_store_path)
    credential_broker = CredentialBroker()

    def _aws_credentials_for(tenant_id: str):
        conn = connection_store.get(tenant_id)
        if conn is None:
            return None          # no connection: fall back to ambient creds
        # Raises rather than silently falling back — a fallback here would run
        # containment against OUR account and look like success.
        return credential_broker.credentials(conn, Grant.CONTAIN)

    containment = ContainmentExecutor(
        settings,
        build_containment_adapters(settings, aws_credentials_for=_aws_credentials_for),
    )
    approvals = ApprovalStore(settings.approval_store_path)
    trajectory = None
    if settings.trajectory_guard_enabled:
        from kronagent.trajectory import TrajectoryConfig, TrajectoryGuard, TrajectoryStateStore
        halt_store = (TrajectoryStateStore(settings.trajectory_state_path)
                      if settings.trajectory_state_path else None)
        trajectory = TrajectoryGuard(
            TrajectoryConfig(
                window_seconds=settings.trajectory_window_seconds,
                max_auto_executions=settings.trajectory_max_auto_executions,
                max_scope_violations=settings.trajectory_max_scope_violations,
                enforce_scope=settings.trajectory_enforce_scope,
            ),
            store=halt_store,
        )
    orchestrator = Orchestrator(
        settings, triage=triage, policy=policy, containment=containment,
        audit=audit, approvals=approvals, threat_intel=threat_intel,
        correlation=correlation, commander=commander, forensics=forensics,
        trajectory=trajectory,
    )

    # active(), not list(): an entry whose TTL has lapsed no longer grants
    # autonomy, so announcing it at boot would misstate the platform's posture.
    allowed = sorted(e.action_class for e in allowlist.active())
    _log("BOOT", "=== Kronagent autonomous threat-defense platform starting ===")
    _log("BOOT", f"mode: {'DRY-RUN (no execution)' if settings.dry_run else 'LIVE EXECUTION'}"
                 f" | kill_switch={settings.kill_switch}")
    _log("BOOT", f"auto-execute allowlist: {allowed or 'EMPTY (all actions need approval)'}")
    _log("BOOT", f"LLM agents (triage + threat-intel + correlation + commander): {llm_status}")
    _log("BOOT", "deterministic agents: forensics (evidence + chain of custody)")
    if trajectory is not None:
        _log("BOOT", f"trajectory guard: ARMED — scope_enforce={settings.trajectory_enforce_scope}, "
                     f"max_auto={settings.trajectory_max_auto_executions}/"
                     f"{settings.trajectory_window_seconds:.0f}s, "
                     f"max_scope_violations={settings.trajectory_max_scope_violations}")
        # A halt survives restarts by design. Say so loudly at boot — otherwise
        # an operator restarts, sees a normal-looking startup, and cannot work
        # out why nothing is being contained.
        if trajectory.halted:
            _log("BOOT", "trajectory guard: ⛔ HALTED FROM A PREVIOUS SESSION — "
                         "ALL containment is blocked")
            _log("BOOT", f"trajectory guard: reason: {trajectory.halt_reason}")
            _log("BOOT", "trajectory guard: inspect with `python3 halt.py status`, "
                         "release with `python3 halt.py clear --by <you> --reason \"<...>\"`")
    else:
        _log("BOOT", "trajectory guard: DISABLED")

    queue: "asyncio.Queue[QueuedFinding]" = asyncio.Queue(maxsize=256)
    stop = asyncio.Event()
    ingestion_done = asyncio.Event()

    # Source selection, most-real first:
    #   1. verified cloud connections  -> poll GuardDuty through the assumed role
    #   2. KRONAGENT_SQS_QUEUE_URL     -> the low-latency production path
    #   3. neither                     -> replay sample events from disk
    #
    # (1) is what makes onboarding a single flow: connecting an account is
    # enough, with no queue to provision and no environment variable to set.
    # (2) and (3) are unchanged — the demo, the SQS testbed and the tests all
    # depend on them.
    healthy = [c for c in connection_store.list()
               if c.state == ConnectionState.HEALTHY]
    unhealthy = [c for c in connection_store.list()
                 if c.state != ConnectionState.HEALTHY]
    sqs_url = os.getenv("KRONAGENT_SQS_QUEUE_URL")

    if healthy:
        for conn in healthy:
            _log("BOOT", f"ingestion: GuardDuty poll for tenant '{conn.tenant_id}' "
                         f"(account {conn.account_id}, region {conn.region})")
        # A connection that verified but is not HEALTHY produces no findings,
        # and silence is exactly how every wiring gap in this path presents.
        for conn in unhealthy:
            _log("BOOT", f"ingestion: SKIPPING tenant '{conn.tenant_id}' — connection "
                         f"state is {conn.state.value}, so it will produce NO findings")
        sources = [
            GuardDutyPollingSource(
                NORMALIZERS["aws"],
                region=conn.region or settings.aws_region,
                tenant_id=conn.tenant_id,
                credentials=(lambda c=conn: credential_broker.credentials(c, Grant.OBSERVE)),
                poll_interval=settings.guardduty_poll_seconds,
            )
            for conn in healthy
        ]
        producer = asyncio.create_task(
            _stream_all(sources, queue, stop)
        )
    elif sqs_url:
        sqs_provider = os.getenv("KRONAGENT_SQS_PROVIDER", "aws")
        _log("BOOT", f"ingestion: SQS long-poll {sqs_url} (provider={sqs_provider}, "
                     f"region {settings.aws_region})")
        source = SqsFindingSource(
            sqs_url, NORMALIZERS[sqs_provider], region=settings.aws_region,
            wait_seconds=settings.sqs_wait_seconds, endpoint_url=settings.sqs_endpoint_url,
        )
        producer = asyncio.create_task(source.stream(queue, stop))
    else:
        if unhealthy:
            _log("BOOT", f"ingestion: {len(unhealthy)} connection(s) exist but none are "
                         f"HEALTHY — falling back to file replay")
        _log("BOOT", f"ingestion: file replay {[p for _, p in replay]} "
                     f"(providers: {sorted({pr for pr, _ in replay})})")
        producer = asyncio.create_task(_replay_files(replay, queue, stop))

    consumer = asyncio.create_task(orchestrator.run(queue, ingestion_done))

    try:
        await producer            # live: until Ctrl-C; replay: finishes on its own
    except (KeyboardInterrupt, asyncio.CancelledError):
        _log("BOOT", "shutdown requested — draining in-flight findings")
    finally:
        stop.set()
        if not producer.done():
            await producer
        ingestion_done.set()      # only now may the consumer exit on an empty queue
        await consumer

    ok, broken = AuditLog.verify(settings.audit_log_path)
    _log("AUDIT", f"chain verification: {'OK' if ok else f'BROKEN at line {broken}'} "
                  f"({settings.audit_log_path})")

    pending = approvals.list(status="pending")
    if pending:
        _log("APPROVAL", f"{len(pending)} action(s) awaiting human approval:")
        for r in pending:
            _log("APPROVAL", f"  {r.request_id}  {r.action_class.value} on {r.target}  "
                            f"(finding {r.finding_id}, severity {r.severity})")
        _log("APPROVAL", "Review with:  python3 approve.py list")
        _log("APPROVAL", "Authorize with:  python3 approve.py approve <id> --by <you> --reason <why>")

    _log("BOOT", f"=== stopped. findings processed: {orchestrator.processed} ===")
    return 0


def cli() -> int:
    """Console-script entry point. Mirrors the __main__ block below so
    `kronagent-slice` and `python3 run_slice.py` behave identically."""
    if len(sys.argv) >= 3:
        prov = sys.argv[1]
        if prov not in NORMALIZERS:
            _log("BOOT", f"unknown provider '{prov}'. Known: {sorted(NORMALIZERS)}")
            return 2
        replay = [(prov, sys.argv[2])]
    elif len(sys.argv) == 2:
        replay = [("aws", sys.argv[1])]
    else:
        replay = _DEFAULT_REPLAY
    try:
        return asyncio.run(main(replay))
    except KeyboardInterrupt:
        _log("BOOT", "interrupted.")
        return 130

if __name__ == "__main__":
    # Usage:
    #   run_slice.py                         -> replay every provider's sample set
    #   run_slice.py <provider> <path.json>  -> replay one file as that provider
    if len(sys.argv) >= 3:
        prov = sys.argv[1]
        if prov not in NORMALIZERS:
            _log("BOOT", f"unknown provider '{prov}'. Known: {sorted(NORMALIZERS)}")
            raise SystemExit(2)
        replay = [(prov, sys.argv[2])]
    elif len(sys.argv) == 2:
        # Back-compat: a bare path is replayed as AWS/GuardDuty.
        replay = [("aws", sys.argv[1])]
    else:
        replay = _DEFAULT_REPLAY
    try:
        raise SystemExit(asyncio.run(main(replay)))
    except KeyboardInterrupt:
        # Ctrl-C during startup/teardown outside the drained window.
        _log("BOOT", "interrupted.")
        raise SystemExit(130)
