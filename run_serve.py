#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — the agent loop and the console in one process.

    python3 run_serve.py                 # live sources only; console on :8000
    python3 run_serve.py --replay        # no live source: replay the samples, then keep serving

This is what the container runs. Until now the image started the console only,
and the agent loop was a second process rewriting the same state files. One
process means one event loop: the console's mutating endpoints and the
pipeline's store writes run on the same loop and cannot interleave, and the
audit log has one writer per process.

Ingestion is chosen exactly as run_slice.py chooses it (healthy cloud
connections, then KRONAGENT_SQS_QUEUE_URL). With neither configured, the
pipeline does not start unless --replay is given: a deployment that silently
replayed sample findings would fill a real audit log with fiction.

Exit codes: 0 after a clean shutdown, 1 when the pipeline crashes or a live
source stops on its own. Either way the console goes down with it, so an
orchestrator (ECS, Kubernetes) restarts the whole task instead of leaving a
console that looks healthy in front of a dead pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import signal
import sys

import uvicorn

import run_slice
from kronagent.config import Settings


class _Server(uvicorn.Server):
    """uvicorn re-raises a captured SIGTERM once it has shut down, which ends
    the process before the pipeline drains. Signals are handled in serve()."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _log(msg: str) -> None:
    print(f"[SERVE] {msg}", flush=True)


async def serve(host: str, port: int, replay: bool) -> int:
    settings = Settings.from_env()
    server = _Server(uvicorn.Config("kronagent.web:app", host=host, port=port, log_level="info"))

    def _shutdown() -> None:
        _log("shutdown requested")
        server.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):     # Windows
            loop.add_signal_handler(sig, _shutdown)

    live = run_slice.live_source_configured(settings)
    pipeline: asyncio.Task | None = None
    if live or replay:
        pipeline = asyncio.create_task(run_slice.main(run_slice._DEFAULT_REPLAY))
    else:
        _log("no live source (no healthy cloud connection, no KRONAGENT_SQS_QUEUE_URL) — "
             "the agent loop is NOT running. Pass --replay to demo on the sample findings.")
    web = asyncio.create_task(server.serve())

    if pipeline is None:
        await web
        return 0

    done, _ = await asyncio.wait({web, pipeline}, return_when=asyncio.FIRST_COMPLETED)
    if pipeline in done:
        crashed = pipeline.exception()
        if crashed is not None:
            _log(f"agent loop crashed ({type(crashed).__name__}: {crashed}) — stopping the console")
            server.should_exit = True
            await web
            return 1
        if live:
            _log("a live source stopped on its own — stopping so the task is restarted")
            server.should_exit = True
            await web
            return 1
        _log("replay finished; the console keeps serving until shutdown")
        await web
        return 0

    # The console stopped first (a signal). Cancelling the pipeline stops
    # ingestion; run_slice.main then drains in-flight findings and verifies
    # the audit chain before returning.
    pipeline.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await pipeline
    return 0


def cli() -> int:
    parser = argparse.ArgumentParser(description="Run the Kronagent agent loop and console together.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address. Defaults to 127.0.0.1; the container passes 0.0.0.0.")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--replay", action="store_true",
                        help="With no live source configured, replay the sample findings.")
    args = parser.parse_args()
    return asyncio.run(serve(args.host, args.port, args.replay))


if __name__ == "__main__":
    sys.exit(cli())
