"""
Finding ingestion.

Two sources behind one async interface, both yielding `QueuedFinding` envelopes
onto the shared work queue:

  * FileReplaySource — reads real-schema GuardDuty finding JSON from disk. Lets
                       the whole pipeline run and be tested with no AWS account.
  * SqsFindingSource — the production path: GuardDuty -> EventBridge -> (optional
                       SNS) -> SQS. Long-polls the queue, unwraps the envelope(s),
                       yields findings, and deletes each message ONLY after the
                       orchestrator has fully processed and audited it.

Delivery semantics (SQS): at-least-once with ack-after-process. A message stays
invisible for the queue's visibility timeout while in flight; it is deleted only
when `QueuedFinding.ack()` runs, which the orchestrator calls after the finding
is handled and audited. If the process crashes mid-processing, the message
reappears after the visibility timeout and is re-processed — a security finding
is never silently lost. This is the deliberate trade: a possible double-response
(idempotent + approval-gated, so safe) over a dropped threat.

Operational requirements for the SQS queue (see deploy/README.md):
  * visibility timeout > max expected per-finding processing time (LLM triage +
    containment). 60s is a safe default for this pipeline.
  * a redrive policy to a dead-letter queue (maxReceiveCount ~5): messages that
    fail to parse are left in place (not deleted) so SQS moves them to the DLQ
    rather than looping forever. Without a DLQ, a poison message redelivers
    every visibility-timeout window.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from pydantic import ValidationError

from .model import Finding

# A normalizer turns one native event dict into a provider-neutral Finding.
# Provided by the caller (from kronagent.providers.NORMALIZERS), so ingestion is
# transport-only and knows nothing about any provider's wire schema.
Normalizer = Callable[[dict], Finding]


@dataclass
class QueuedFinding:
    """A finding on the internal work queue, plus the ack that retires it from
    the upstream source. `ack()` is called by the orchestrator exactly once,
    after processing + auditing completes."""

    finding: Finding
    _ack: Callable[[], Awaitable[None]]

    async def ack(self) -> None:
        await self._ack()


async def _noop_ack() -> None:
    return None


class FileReplaySource:
    def __init__(self, path: str, normalizer: Normalizer, *, interval: float = 1.0) -> None:
        self._path = path
        self._normalizer = normalizer
        self._interval = interval

    async def stream(self, queue: "asyncio.Queue[QueuedFinding]", stop: asyncio.Event) -> None:
        with open(self._path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        events = raw if isinstance(raw, list) else [raw]

        for item in events:
            if stop.is_set():
                break
            try:
                finding = self._normalizer(item)
            except (ValidationError, KeyError, ValueError) as exc:
                print(f"[INGEST] skipping malformed event: {exc}", flush=True)
                continue
            # File replay has nothing to retire upstream — ack is a no-op.
            await queue.put(QueuedFinding(finding=finding, _ack=_noop_ack))
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass


class SqsFindingSource:
    """Production ingestion: long-poll an SQS queue fed by EventBridge (optionally
    via SNS). boto3 is imported lazily so importing this module never requires AWS.

    Messages are deleted only via `QueuedFinding.ack()` after full processing —
    see the module docstring for the at-least-once rationale.
    """

    # Backoff bounds for transient SQS/receive errors (throttling, network).
    _RECEIVE_BASE_BACKOFF = 1.0
    _RECEIVE_MAX_BACKOFF = 30.0

    def __init__(self, queue_url: str, normalizer: Normalizer, *, region: str,
                 wait_seconds: int = 20, endpoint_url: str = "") -> None:
        self._queue_url = queue_url
        self._normalizer = normalizer
        self._region = region
        self._wait_seconds = wait_seconds
        # Empty => real AWS. Set to a local emulator (moto/ElasticMQ) for the
        # testbed, or a VPC endpoint in production.
        self._endpoint_url = endpoint_url or None
        self._sqs = None

    def _client(self):
        if self._sqs is None:
            import boto3  # local import: module stays importable without AWS
            self._sqs = boto3.client(
                "sqs", region_name=self._region, endpoint_url=self._endpoint_url
            )
        return self._sqs

    async def stream(self, queue: "asyncio.Queue[QueuedFinding]", stop: asyncio.Event) -> None:
        sqs = self._client()
        backoff = self._RECEIVE_BASE_BACKOFF

        while not stop.is_set():
            try:
                resp = await asyncio.to_thread(
                    sqs.receive_message,
                    QueueUrl=self._queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=self._wait_seconds,
                    AttributeNames=["ApproximateReceiveCount"],
                )
                backoff = self._RECEIVE_BASE_BACKOFF  # reset after a clean poll
            except Exception as exc:  # noqa: BLE001 - a receive error must not kill ingestion
                print(f"[INGEST] SQS receive failed, backing off {backoff:.0f}s: "
                      f"{type(exc).__name__}: {exc}", flush=True)
                await self._interruptible_sleep(stop, backoff)
                backoff = min(backoff * 2, self._RECEIVE_MAX_BACKOFF)
                continue

            for msg in resp.get("Messages", []):
                receipt = msg["ReceiptHandle"]
                finding = self._unwrap(msg.get("Body", ""), self._normalizer)

                if finding is None:
                    # Poison message: leave it for DLQ redrive rather than delete
                    # (deleting would silently lose it). SQS moves it to the DLQ
                    # once ApproximateReceiveCount exceeds the redrive maxReceiveCount.
                    recv = msg.get("Attributes", {}).get("ApproximateReceiveCount", "?")
                    print(f"[INGEST] unparseable message left for DLQ redrive "
                          f"(receive count {recv})", flush=True)
                    continue

                await queue.put(QueuedFinding(
                    finding=finding,
                    _ack=self._make_ack(receipt),
                ))

    def _make_ack(self, receipt_handle: str) -> Callable[[], Awaitable[None]]:
        async def _ack() -> None:
            await asyncio.to_thread(
                self._client().delete_message,
                QueueUrl=self._queue_url,
                ReceiptHandle=receipt_handle,
            )
        return _ack

    @staticmethod
    async def _interruptible_sleep(stop: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    @staticmethod
    def _unwrap(body: str, normalizer: Normalizer) -> Optional[Finding]:
        """Unwrap the native event from an SQS message body and normalize it.

        Handles both delivery topologies:
          * EventBridge -> SQS:        {"detail-type": ..., "detail": <event>}
          * EventBridge -> SNS -> SQS: {"Type": "Notification",
                                        "Message": "<stringified EventBridge JSON>"}
        and a bare event (defensive). The provider's normalizer does the final
        native-event -> Finding conversion.
        """
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError as exc:
            print(f"[INGEST] message body is not JSON: {exc}", flush=True)
            return None

        # SNS notification wraps the real payload as a JSON string under "Message".
        if isinstance(envelope, dict) and envelope.get("Type") == "Notification" \
                and isinstance(envelope.get("Message"), str):
            try:
                envelope = json.loads(envelope["Message"])
            except json.JSONDecodeError as exc:
                print(f"[INGEST] SNS Message is not JSON: {exc}", flush=True)
                return None

        # EventBridge wraps the event under "detail"; otherwise treat as bare.
        detail = envelope.get("detail", envelope) if isinstance(envelope, dict) else envelope

        try:
            return normalizer(detail)
        except (ValidationError, KeyError, ValueError) as exc:
            print(f"[INGEST] payload did not normalize to a Finding: {exc}", flush=True)
            return None


class GuardDutyPollingSource:
    """Poll GuardDuty directly, through a tenant's assumed role.

    This is the path that makes onboarding a single flow. The alternative —
    GuardDuty -> EventBridge -> SQS — is lower latency but needs a queue, a
    rule, a queue policy and extra IAM provisioned in the customer's account.
    That is six manual steps between "connection verified" and "findings
    arriving", and it was the whole gap between a working engine and a product
    someone could actually start using.

    The observe role already grants `guardduty:ListDetectors`, `ListFindings`
    and `GetFindings` (deploy/cloudformation/kronagent-observe-role.json), so
    polling needs **nothing provisioned beyond the role the customer already
    granted**. Latency is one poll interval rather than seconds, which is the
    right trade for shadow mode, where nothing executes. `SqsFindingSource`
    remains the low-latency production option.

    Two details that matter operationally:

      * **Watermark.** Only findings updated at or after the watermark are
        fetched, and the watermark starts at `now - lookback_minutes`. Without
        it, a restart would replay the customer's entire GuardDuty history into
        the approval queue — turning a routine deploy into an incident.
      * **Dedupe on (id, updatedAt).** GuardDuty *updates* findings in place, so
        the same id legitimately reappears. Keying on the pair means a genuinely
        updated finding is reprocessed while an unchanged one is not.

    `ack()` is a no-op: polling has no message to retire, and the watermark plus
    dedupe already make redelivery idempotent. The orchestrator's
    ack-after-process contract is unaffected.
    """

    _POLL_BASE_BACKOFF = 5.0
    _POLL_MAX_BACKOFF = 300.0
    # Bounds the dedupe set. Well above any realistic per-poll volume, and
    # bounded so a long-running process cannot grow it without limit.
    _SEEN_LIMIT = 5000

    def __init__(self, normalizer: Normalizer, *, region: str,
                 tenant_id: str = "default",
                 credentials: Optional[Callable[[], dict]] = None,
                 poll_interval: float = 60.0,
                 lookback_minutes: int = 60,
                 max_findings_per_poll: int = 50,
                 client_factory: Optional[Callable[[], object]] = None) -> None:
        self._normalizer = normalizer
        self._region = region
        # The SaaS seam. Self-hosted passes "default"; a multi-tenant deployment
        # passes the connection's tenant and nothing else in the pipeline
        # changes, because every downstream store is already tenant-scoped.
        self._tenant_id = tenant_id
        # Returns freshly-assumed role credentials. None => the process's own
        # ambient credentials, which is correct for a local single-account run.
        self._credentials = credentials
        self._poll_interval = poll_interval
        self._max_per_poll = max_findings_per_poll
        self._client_factory = client_factory
        self._gd = None

        from datetime import datetime, timedelta, timezone
        start = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        self._watermark_ms = int(start.timestamp() * 1000)
        self._seen: set[tuple[str, str]] = set()

    def _client(self):
        if self._client_factory is not None:
            return self._client_factory()
        if self._gd is None:
            import boto3  # local import: module stays importable without AWS
            kwargs = {"region_name": self._region}
            if self._credentials is not None:
                creds = self._credentials()
                kwargs.update(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
            self._gd = boto3.client("guardduty", **kwargs)
        return self._gd

    async def stream(self, queue: "asyncio.Queue[QueuedFinding]", stop: asyncio.Event) -> None:
        backoff = self._POLL_BASE_BACKOFF
        while not stop.is_set():
            try:
                emitted = await asyncio.to_thread(self._poll_once)
                backoff = self._POLL_BASE_BACKOFF
            except Exception as exc:  # noqa: BLE001 - a poll error must not kill ingestion
                print(f"[INGEST] GuardDuty poll failed for tenant "
                      f"'{self._tenant_id}', backing off {backoff:.0f}s: "
                      f"{type(exc).__name__}: {exc}", flush=True)
                await self._sleep(stop, backoff)
                backoff = min(backoff * 2, self._POLL_MAX_BACKOFF)
                continue

            for finding in emitted:
                await queue.put(QueuedFinding(finding=finding, _ack=_noop_ack))

            await self._sleep(stop, self._poll_interval)

    def _poll_once(self) -> list[Finding]:
        """One synchronous poll cycle. Returns the findings new since the
        watermark, and advances it."""
        gd = self._client()
        findings: list[Finding] = []

        detectors = gd.list_detectors().get("DetectorIds", [])
        for detector_id in detectors:
            listed = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"updatedAt": {"Gte": self._watermark_ms}}},
                MaxResults=self._max_per_poll,
            )
            ids = listed.get("FindingIds", [])
            if not ids:
                continue

            for raw in gd.get_findings(DetectorId=detector_id,
                                       FindingIds=ids).get("Findings", []):
                key = (str(raw.get("Id", "")), str(raw.get("UpdatedAt", "")))
                if key in self._seen:
                    continue
                self._seen.add(key)

                try:
                    finding = self._normalizer(raw)
                except Exception as exc:  # noqa: BLE001 - one bad finding must not stop the poll
                    print(f"[INGEST] GuardDuty finding {key[0]} failed to "
                          f"normalize: {type(exc).__name__}: {exc}", flush=True)
                    continue

                findings.append(finding.model_copy(update={"tenant_id": self._tenant_id}))
                self._advance_watermark(raw.get("UpdatedAt"))

        self._trim_seen()
        return findings

    def _advance_watermark(self, updated_at) -> None:
        """Move the watermark to the newest finding seen.

        Tolerant of the shapes GuardDuty returns across SDK versions (ISO string
        or datetime); an unparseable value leaves the watermark alone rather
        than jumping it forward and skipping findings.
        """
        if not updated_at:
            return
        from datetime import datetime, timezone
        try:
            if isinstance(updated_at, datetime):
                dt = updated_at
            else:
                dt = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self._watermark_ms = max(self._watermark_ms, int(dt.timestamp() * 1000))
        except (ValueError, TypeError):
            return

    def _trim_seen(self) -> None:
        if len(self._seen) > self._SEEN_LIMIT:
            # Cheap bound. Anything dropped is older than the watermark, so it
            # cannot be re-fetched anyway.
            self._seen = set(list(self._seen)[-self._SEEN_LIMIT // 2:])

    @staticmethod
    async def _sleep(stop: asyncio.Event, seconds: float) -> None:
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass
