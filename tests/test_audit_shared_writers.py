"""
Several AuditLog instances on one file — the console, the agent loop and the
CLIs each hold their own — must extend one chain, not fork it.
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing

from kronagent.audit import AuditLog
from kronagent.schemas import AuditRecord


def _record(n: int) -> AuditRecord:
    return AuditRecord(finding_id=f"f-{n}", stage="test", payload={"n": n})


def test_interleaved_instances_extend_one_chain(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    console, agent = AuditLog(path), AuditLog(path)

    async def go() -> None:
        for n in range(10):
            await (console if n % 3 == 0 else agent).record(_record(n))

    asyncio.run(go())
    assert AuditLog.verify(path) == (True, None)


def test_a_log_written_elsewhere_since_boot_is_continued(tmp_path) -> None:
    """An instance created before another process appended must still link to
    the newest record, not to the one it saw at construction."""
    path = str(tmp_path / "audit.jsonl")
    early = AuditLog(path)
    asyncio.run(AuditLog(path).record(_record(1)))
    asyncio.run(early.record(_record(2)))
    lines = [json.loads(line) for line in open(path)]
    assert lines[1]["_prev"] == lines[0]["_hash"]
    assert AuditLog.verify(path) == (True, None)


def test_a_junk_tail_line_does_not_break_the_next_append(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    asyncio.run(log.record(_record(1)))
    with open(path, "a") as fh:
        fh.write("not json\n")
    asyncio.run(AuditLog(path).record(_record(2)))
    records = [json.loads(line) for line in open(path) if line.startswith("{")]
    assert records[1]["_prev"] == records[0]["_hash"]


def _write_many(path: str, start: int) -> None:
    async def go() -> None:
        log = AuditLog(path)
        for n in range(start, start + 25):
            await log.record(_record(n))
    asyncio.run(go())


def test_concurrent_processes_extend_one_chain(tmp_path) -> None:
    path = str(tmp_path / "audit.jsonl")
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_write_many, args=(path, i * 100)) for i in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0
    assert sum(1 for _ in open(path)) == 75
    assert AuditLog.verify(path) == (True, None)


def test_records_deleted_under_a_running_writer_stay_visible(tmp_path) -> None:
    """Continuing from the file's tail must not launder a truncation: a writer
    whose own last record has vanished links to it anyway, so verify() fails."""
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)

    async def write(n: int) -> None:
        await log.record(_record(n))

    for n in range(3):
        asyncio.run(write(n))
    lines = open(path).readlines()
    with open(path, "w") as fh:
        fh.writelines(lines[:1])          # someone deletes the last two records
    asyncio.run(write(3))
    ok, _ = AuditLog.verify(path)
    assert not ok
