"""
The onboarding funnel: a verified connection produces findings, by itself.

Three seams were unjoined, and each piece on either side was already well built:

  1. Connect -> ingestion. `ConnectionStore` was referenced only by the web API,
     never by the pipeline. Verifying a connection started nothing, so a customer
     completed the 3-click flow, saw `healthy`, and nothing happened. Someone had
     to hand-set KRONAGENT_SQS_QUEUE_URL and restart.
  2. Ingestion -> tenant. No normalizer except Cloudflare set `tenant_id`, so
     every finding landed in `default` and the tenant-scoped stores were
     unreachable through the real pipeline.
  3. Tenant -> credentials. `build_containment_adapters(aws_credentials_for=...)`
     existed and was documented, but `run_slice.py` never passed it, so AWS
     containment would have run against OUR ambient credentials rather than the
     role the customer granted.

That was the whole distance between a working engine and something a stranger
could use. These tests pin the joins.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from kronagent.ingestion import GuardDutyPollingSource
from kronagent.providers import NORMALIZERS

REPO_ROOT = Path(__file__).resolve().parent.parent


class FakeGuardDuty:
    """A GuardDuty client double. Records the criteria it was asked for, so the
    watermark can be asserted on rather than inferred."""

    def __init__(self, findings: list[dict]) -> None:
        self._findings = findings
        self.criteria_seen: list[int] = []

    def list_detectors(self) -> dict:
        return {"DetectorIds": ["det-1"]}

    def list_findings(self, *, DetectorId, FindingCriteria, MaxResults):  # noqa: N803
        gte = FindingCriteria["Criterion"]["updatedAt"]["Gte"]
        self.criteria_seen.append(gte)
        self._matched = [f for f in self._findings
                         if _epoch_ms(f["UpdatedAt"]) >= gte]
        return {"FindingIds": [f["Id"] for f in self._matched]}

    def get_findings(self, *, DetectorId, FindingIds):  # noqa: N803
        return {"Findings": [f for f in self._matched if f["Id"] in FindingIds]}


def _epoch_ms(iso: str) -> int:
    from datetime import datetime, timezone
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _guardduty_finding(fid: str, updated: str) -> dict:
    raw = json.loads((REPO_ROOT / "samples" / "guardduty_findings.json").read_text())[0]
    return {**raw, "Id": fid, "UpdatedAt": updated}


def _source(client: FakeGuardDuty, **kw) -> GuardDutyPollingSource:
    return GuardDutyPollingSource(
        NORMALIZERS["aws"], region="us-east-1",
        client_factory=lambda: client, **kw,
    )


# --------------------------------------------------------------------------- #
# Polling
# --------------------------------------------------------------------------- #

def test_poll_emits_normalized_findings() -> None:
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    client = FakeGuardDuty([_guardduty_finding("f-1", recent)])

    findings = _source(client)._poll_once()

    assert [f.finding_id for f in findings] == ["f-1"]
    assert findings[0].provider == "aws"
    assert findings[0].resources, "normalization must survive the polling path"


def test_repolling_yields_nothing_new() -> None:
    """GuardDuty updates findings in place, so the same id legitimately
    reappears. Without dedupe every poll would re-queue the same incident."""
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    source = _source(FakeGuardDuty([_guardduty_finding("f-1", recent)]))

    assert len(source._poll_once()) == 1
    assert source._poll_once() == []


def test_an_updated_finding_is_reprocessed() -> None:
    """The converse: a finding GuardDuty genuinely updated must come through
    again, because its assessment may have changed."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    first = (now - timedelta(minutes=5)).isoformat()
    later = (now - timedelta(minutes=1)).isoformat()

    client = FakeGuardDuty([_guardduty_finding("f-1", first)])
    source = _source(client)
    assert len(source._poll_once()) == 1

    client._findings = [_guardduty_finding("f-1", later)]
    assert len(source._poll_once()) == 1, "an updated finding must be reprocessed"


def test_history_is_not_replayed_on_start() -> None:
    """THE operational property. Without a watermark, a restart would flood the
    approval queue with the customer's entire GuardDuty history — turning a
    routine deploy into an incident."""
    old = "2020-01-01T00:00:00Z"
    client = FakeGuardDuty([_guardduty_finding("ancient", old)])

    assert _source(client, lookback_minutes=60)._poll_once() == []


def test_watermark_advances_past_processed_findings() -> None:
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1))
    client = FakeGuardDuty([_guardduty_finding("f-1", recent.isoformat())])
    source = _source(client)

    before = source._watermark_ms
    source._poll_once()
    assert source._watermark_ms >= before
    assert source._watermark_ms >= _epoch_ms(recent.isoformat())


def test_a_malformed_finding_does_not_stop_the_poll() -> None:
    """One unparseable finding must not deny the customer every other one."""
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    good = _guardduty_finding("good", recent)
    bad = {"Id": "bad", "UpdatedAt": recent}  # missing Type/Severity

    findings = _source(FakeGuardDuty([bad, good]))._poll_once()
    assert [f.finding_id for f in findings] == ["good"]


# --------------------------------------------------------------------------- #
# The tenant seam
# --------------------------------------------------------------------------- #

def test_findings_carry_the_connections_tenant() -> None:
    """Seam 2. Every downstream store is already tenant-scoped; this is the only
    place a finding acquires the tenant, so without it the whole multi-tenant
    layer is unreachable through the real pipeline."""
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    client = FakeGuardDuty([_guardduty_finding("f-1", recent)])

    findings = _source(client, tenant_id="acme")._poll_once()
    assert findings[0].tenant_id == "acme"


def test_default_tenant_for_self_hosted() -> None:
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    findings = _source(FakeGuardDuty([_guardduty_finding("f-1", recent)]))._poll_once()
    assert findings[0].tenant_id == "default"


async def test_stream_puts_findings_on_the_queue() -> None:
    from datetime import datetime, timedelta, timezone
    recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    source = _source(FakeGuardDuty([_guardduty_finding("f-1", recent)]),
                     poll_interval=0.05)

    queue: asyncio.Queue = asyncio.Queue()
    stop = asyncio.Event()
    task = asyncio.create_task(source.stream(queue, stop))
    item = await asyncio.wait_for(queue.get(), timeout=5.0)
    stop.set()
    await asyncio.wait_for(task, timeout=5.0)

    assert item.finding.finding_id == "f-1"
    await item.ack()  # no-op, but the orchestrator calls it unconditionally


async def test_a_failing_poll_does_not_kill_ingestion() -> None:
    """A tenant's transient GuardDuty error must not end ingestion for good."""
    class Broken:
        def list_detectors(self):
            raise RuntimeError("throttled")

    source = _source(Broken(), poll_interval=0.05)
    source._POLL_BASE_BACKOFF = 0.01
    queue: asyncio.Queue = asyncio.Queue()
    stop = asyncio.Event()
    task = asyncio.create_task(source.stream(queue, stop))
    await asyncio.sleep(0.1)
    assert not task.done(), "ingestion died on a transient poll failure"
    stop.set()
    await asyncio.wait_for(task, timeout=5.0)


# --------------------------------------------------------------------------- #
# The credential seam — an invariant, in the style of the three already added
# --------------------------------------------------------------------------- #

def test_the_pipeline_brokers_credentials_for_aws_containment() -> None:
    """Seam 3, guarded the way the other recurring gaps now are
    (test_policy_consistency, the router scan, test_provider_execution_honesty).

    `run_slice.py` must pass `aws_credentials_for` when building containment
    adapters. Without it, AWS actions run under whatever ambient credentials the
    process holds — against OUR account rather than the customer's — which is
    the most dangerous possible failure because it would look like success.
    """
    source = (REPO_ROOT / "run_slice.py").read_text()
    assert "build_containment_adapters(" in source
    assert "aws_credentials_for=" in source, (
        "run_slice.py builds containment adapters without a credential "
        "resolver: AWS containment would use ambient process credentials "
        "instead of the tenant's assumed role."
    )


def test_the_pipeline_starts_ingestion_from_connections() -> None:
    """Seam 1. Verifying a connection has to actually start something."""
    source = (REPO_ROOT / "run_slice.py").read_text()
    # Construction, not import: `"GuardDutyPollingSource" in source` is satisfied
    # by the import line alone, so it would pass even with the source never
    # instantiated. Verified by mutation — the weaker check did not fail.
    assert "ConnectionStore(" in source, "the pipeline never reads connections"
    assert "GuardDutyPollingSource(" in source, (
        "the pipeline imports the polling source but never constructs one, so a "
        "verified connection still produces no findings."
    )


def test_the_file_replay_and_sqs_paths_survive() -> None:
    """The demo, the SQS testbed and the tests all depend on these."""
    source = (REPO_ROOT / "run_slice.py").read_text()
    assert "SqsFindingSource(" in source
    assert "_replay_files(" in source
