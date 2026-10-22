"""
run_serve: one process for the agent loop and the console. The console server
and the pipeline are stand-ins; what is under test is how the two are tied
together — who stops whom, and with what exit code.
"""

from __future__ import annotations

import asyncio
import os
import signal

import pytest

import run_serve
import run_slice


class FakeServer:
    def __init__(self, config) -> None:
        self.should_exit = False

    async def serve(self) -> None:
        while not self.should_exit:
            await asyncio.sleep(0.01)


@pytest.fixture
def harness(monkeypatch):
    state = {"main_calls": 0, "drained": False}
    monkeypatch.setattr(run_serve, "_Server", FakeServer)

    def use(main, live: bool = False):
        async def counted(replay):
            state["main_calls"] += 1
            return await main(state)
        monkeypatch.setattr(run_slice, "main", counted)
        monkeypatch.setattr(run_slice, "live_source_configured", lambda settings: live)
    return state, use


def _sigterm_soon(delay: float = 0.1) -> None:
    asyncio.get_running_loop().call_later(delay, os.kill, os.getpid(), signal.SIGTERM)


async def _forever(state) -> int:
    try:
        await asyncio.sleep(3600)
    except asyncio.CancelledError:
        state["drained"] = True       # run_slice.main drains on cancellation
    return 0


async def _crash(state) -> int:
    raise RuntimeError("boom")


async def _done(state) -> int:
    return 0


async def test_without_a_live_source_or_replay_the_loop_does_not_start(harness) -> None:
    state, use = harness
    use(_forever, live=False)
    _sigterm_soon()
    assert await run_serve.serve("127.0.0.1", 0, replay=False) == 0
    assert state["main_calls"] == 0


async def test_a_signal_stops_the_console_and_drains_the_pipeline(harness) -> None:
    state, use = harness
    use(_forever, live=True)
    _sigterm_soon()
    assert await run_serve.serve("127.0.0.1", 0, replay=False) == 0
    assert state["main_calls"] == 1 and state["drained"]


async def test_a_crashed_pipeline_takes_the_console_down(harness) -> None:
    _, use = harness
    use(_crash, live=True)
    assert await run_serve.serve("127.0.0.1", 0, replay=False) == 1


async def test_a_live_source_that_ends_is_a_failure(harness) -> None:
    _, use = harness
    use(_done, live=True)
    assert await run_serve.serve("127.0.0.1", 0, replay=False) == 1


async def test_a_finished_replay_leaves_the_console_serving(harness) -> None:
    state, use = harness
    use(_done, live=False)
    _sigterm_soon(0.2)
    assert await run_serve.serve("127.0.0.1", 0, replay=True) == 0
    assert state["main_calls"] == 1


def test_live_source_detection(monkeypatch, tmp_path) -> None:
    from kronagent.config import Settings
    monkeypatch.setenv("KRONAGENT_CONNECTION_PATH", str(tmp_path / "none.json"))
    monkeypatch.delenv("KRONAGENT_SQS_QUEUE_URL", raising=False)
    assert run_slice.live_source_configured(Settings.from_env()) is False
    monkeypatch.setenv("KRONAGENT_SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/1/q")
    assert run_slice.live_source_configured(Settings.from_env()) is True
