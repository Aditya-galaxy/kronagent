"""
Append-only, hash-chained audit log.

Every decision and action the platform takes is recorded here as one JSON line.
Each record carries the SHA-256 of the previous record, forming a chain: any
after-the-fact edit or deletion of a past entry breaks verification of every
later entry. This is the forensic backbone — when the platform acts on
production, you must be able to reconstruct exactly what happened and why, and
prove the record wasn't altered.

In production this backs onto a WORM store (S3 Object Lock / DynamoDB with a
stream to an immutable sink); the local implementation is a plain JSONL file
with identical chaining semantics so the logic is the same and testable.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from typing import Any, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: in-process ordering only
    fcntl = None  # type: ignore[assignment]

from .schemas import AuditRecord

_GENESIS = "0" * 64
_TAIL_BYTES = 64 * 1024     # far larger than any one record

_log = logging.getLogger(__name__)


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic serialization the chain hash is computed over."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _hash_entry(prev_hash: str, canonical_body: str) -> str:
    return hashlib.sha256((prev_hash + canonical_body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._last_hash = self._recover_last_hash()

    @staticmethod
    def _tail_hash(fh) -> Optional[str]:
        """The hash of the last record in a log opened in binary, read from
        its end. None means the tail held no record (junk only)."""
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return _GENESIS
        fh.seek(max(0, size - _TAIL_BYTES))
        for line in reversed(fh.read().splitlines()):
            try:
                return json.loads(line)["_hash"]
            except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
                continue
        return None

    @staticmethod
    def _holds(fh, entry_hash: str) -> bool:
        """Whether a record with this hash is still in the log."""
        if entry_hash == _GENESIS:
            return True
        needle = f'"_hash": "{entry_hash}"'.encode()
        fh.seek(0)
        return any(needle in line for line in fh)

    def _recover_last_hash(self) -> str:
        """Resume the chain from an existing log so restarts don't fork it."""
        if not os.path.exists(self._path):
            return _GENESIS
        last = _GENESIS
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["_hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    async def record(self, entry: AuditRecord) -> str:
        """Append one entry durably; returns its chain hash."""
        # The chain continues from the file, not from this instance's memory.
        # The console, the agent loop and the CLIs each hold their own
        # AuditLog on the same path; linking to a remembered hash forked the
        # chain the moment two of them interleaved, and verify() then reported
        # tampering that never happened. The file lock makes read-tail-then-
        # append atomic across instances and processes.
        async with self._lock:
            record = entry.model_dump()
            canonical = _canonical(record)
            with open(self._path, "ab+") as fh:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    prev = self._tail_hash(fh)
                    if prev is None:
                        prev = self._recover_last_hash()
                    # Another writer appending since our last record is
                    # normal. Our last record being GONE is not: linking to the
                    # new tail would quietly paper over deleted entries, so
                    # keep linking to ours and let verify() show the gap.
                    if prev != self._last_hash and not self._holds(fh, self._last_hash):
                        _log.error("audit log %s no longer holds record %s that this process "
                                   "wrote or read; the chain is left broken so verification "
                                   "reports it", self._path, self._last_hash[:12])
                        prev = self._last_hash
                    entry_hash = _hash_entry(prev, canonical)
                    envelope = {"_prev": prev, "_hash": entry_hash, "record": record}
                    fh.seek(0, os.SEEK_END)
                    fh.write((json.dumps(envelope) + "\n").encode("utf-8"))
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            self._last_hash = entry_hash
            return entry_hash

    def records(self) -> list[dict[str, Any]]:
        """This log's records, oldest first. The instance-level counterpart to
        `read_records`, for callers that already hold the log they wrote to."""
        return self.read_records(self._path)

    @staticmethod
    def read_records(path: str) -> list[dict[str, Any]]:
        """Every record in the log, oldest first, skipping unparseable lines.

        Tamper-evidence is `verify()`'s job; this is the plain read path for
        tooling that reports on history — e.g. `promote.py review` asking which
        allowlist entries lapsed since anyone last looked.
        """
        records: list[dict[str, Any]] = []
        if not os.path.exists(path):
            return records
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line).get("record")
                except json.JSONDecodeError:
                    continue
                if record:
                    records.append(record)
        return records

    @staticmethod
    def verify(path: str) -> tuple[bool, Optional[int]]:
        """Verify the whole chain. Returns (ok, first_broken_line_or_None)."""
        prev = _GENESIS
        if not os.path.exists(path):
            return True, None
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                env = json.loads(line)
                recomputed = _hash_entry(env["_prev"], _canonical(env["record"]))
                if env["_prev"] != prev or env["_hash"] != recomputed:
                    return False, n
                prev = env["_hash"]
        return True, None
