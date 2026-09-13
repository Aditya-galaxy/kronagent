"""
ContainmentExecutor — provider-agnostic dispatch and the dry-run/kill-switch
safety gate. Uses FakeContainmentAdapter (conftest) so these tests never touch
boto3 or the kubernetes client.
"""

from __future__ import annotations

import pytest

from kronagent.containment import ContainmentExecutor
from kronagent.schemas import ActionClass

from .conftest import FakeContainmentAdapter, make_action, make_decision


def _executor(settings, adapter: FakeContainmentAdapter) -> ContainmentExecutor:
    return ContainmentExecutor(settings, {adapter.provider: adapter})


async def test_plan_is_always_computed_even_when_blocked(settings) -> None:
    """Design invariant from the module docstring: the plan (api_calls +
    rollback) is recorded for every action, even one that never runs."""
    adapter = FakeContainmentAdapter()
    executor = _executor(settings, adapter)
    action = make_action(provider="fake", action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = make_decision(action_class=ActionClass.DISABLE_ACCESS_KEY, disposition="blocked")

    outcome = await executor.execute(action, decision)

    assert outcome.api_calls  # non-empty -- adapter.plan() ran
    assert outcome.rollback_hint
    assert outcome.executed is False
    assert "BLOCKED" in outcome.detail
    assert adapter.perform_calls == []  # plan-only, never performed


async def test_requires_approval_never_executes(settings) -> None:
    adapter = FakeContainmentAdapter()
    executor = _executor(settings, adapter)
    action = make_action(provider="fake", action_class=ActionClass.TERMINATE_INSTANCE)
    decision = make_decision(action_class=ActionClass.TERMINATE_INSTANCE, disposition="requires_approval")

    outcome = await executor.execute(action, decision)

    assert outcome.executed is False
    assert "AWAITING APPROVAL" in outcome.detail
    assert adapter.perform_calls == []


async def test_auto_execute_in_dry_run_plans_but_does_not_perform(settings) -> None:
    assert settings.dry_run is True  # sanity: the fixture default
    adapter = FakeContainmentAdapter()
    executor = _executor(settings, adapter)
    action = make_action(provider="fake", action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = make_decision(action_class=ActionClass.DISABLE_ACCESS_KEY, disposition="auto_execute")

    outcome = await executor.execute(action, decision)

    assert outcome.executed is False
    assert outcome.dry_run is True
    assert "DRY-RUN" in outcome.detail
    assert adapter.perform_calls == []


async def test_auto_execute_live_calls_perform(settings_live) -> None:
    adapter = FakeContainmentAdapter()
    executor = _executor(settings_live, adapter)
    action = make_action(provider="fake", action_class=ActionClass.DISABLE_ACCESS_KEY, target="AKIA-live")
    decision = make_decision(action_class=ActionClass.DISABLE_ACCESS_KEY, disposition="auto_execute")

    outcome = await executor.execute(action, decision)

    assert outcome.executed is True
    assert outcome.dry_run is False
    assert "EXECUTED" in outcome.detail
    assert len(adapter.perform_calls) == 1
    assert adapter.perform_calls[0].target == "AKIA-live"


async def test_live_execution_failure_is_captured_not_raised(settings_live) -> None:
    """A provider execution failure must produce a failed ActionOutcome, never
    propagate and crash the orchestrator loop."""
    adapter = FakeContainmentAdapter(raise_on_perform=RuntimeError("boto3 said no"))
    executor = _executor(settings_live, adapter)
    action = make_action(provider="fake", action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = make_decision(action_class=ActionClass.DISABLE_ACCESS_KEY, disposition="auto_execute")

    outcome = await executor.execute(action, decision)

    assert outcome.executed is False
    assert outcome.error == "boto3 said no"
    assert "EXECUTION FAILED" in outcome.detail
    assert "RuntimeError" in outcome.detail


async def test_unregistered_provider_raises(settings) -> None:
    executor = ContainmentExecutor(settings, {})  # no adapters registered
    action = make_action(provider="azure", action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = make_decision(action_class=ActionClass.DISABLE_ACCESS_KEY, disposition="blocked")

    with pytest.raises(KeyError):
        await executor.execute(action, decision)


@pytest.fixture
def settings_live(settings):
    import dataclasses
    return dataclasses.replace(settings, dry_run=False)
