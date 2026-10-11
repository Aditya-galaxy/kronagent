"""
Containment executor — generic safety logic, provider-specific execution.

The dangerous decisions live here and are provider-agnostic: whether an action
is blocked, awaits approval, is planned-only (dry-run), or actually executes.
The concrete "what API calls does this action make" is delegated to the
provider's ContainmentAdapter (kronagent/providers/*.py), selected by the action's
`provider` field.

Design principle (unchanged across the provider refactor): the *plan* — the
exact calls that would be made, plus the precise rollback — is computed for
every action, always, and recorded, even when the action is not executed.
Execution happens only when the policy engine returned `auto_execute` AND the
global dry_run flag is off. Cloud/cluster clients are built lazily inside the
adapters, so the whole pipeline runs in dry-run with no credentials.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Protocol

from .config import Settings
from .schemas import ActionOutcome, PolicyDecision, ProposedAction, ReleaseOutcome


class ContainmentAdapter(Protocol):
    """What each provider implements. `plan` is pure (no I/O); `perform` does the
    real cloud/cluster calls and returns (detail, concrete_rollback)."""

    provider: str

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]: ...
    async def perform(self, action: ProposedAction) -> tuple[str, str]: ...

    # Optional. An adapter that can undo an action implements both:
    #   plan_release(action) -> (api_calls, summary), or None if it can't undo
    #                           this action class;
    #   async release(action) -> detail of what was undone.
    # A release works from the resource's current state, not from numbers
    # remembered when the action ran, so it is safe to run twice.


class ContainmentExecutor:
    def __init__(self, settings: Settings, adapters: dict[str, ContainmentAdapter]) -> None:
        self._settings = settings
        self._adapters = adapters

    def _adapter(self, action: ProposedAction) -> ContainmentAdapter:
        adapter = self._adapters.get(action.provider)
        if adapter is None:
            raise KeyError(f"no containment adapter registered for provider '{action.provider}'")
        return adapter

    async def execute(self, action: ProposedAction, decision: PolicyDecision) -> ActionOutcome:
        """Compute the plan; execute only if authorized and not in dry-run."""
        adapter = self._adapter(action)
        api_calls, rollback_hint, detail = adapter.plan(action)

        if decision.disposition == "blocked":
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=self._settings.dry_run,
                detail=f"BLOCKED — {decision.reason}", rollback_hint=rollback_hint,
                api_calls=api_calls,
            )

        if decision.disposition == "requires_approval":
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=self._settings.dry_run,
                detail=f"AWAITING APPROVAL — {decision.reason}. Plan ready to run on approval.",
                rollback_hint=rollback_hint, api_calls=api_calls,
            )

        # disposition == auto_execute
        if self._settings.dry_run:
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=True,
                detail=f"DRY-RUN — would auto-execute: {detail}",
                rollback_hint=rollback_hint, api_calls=api_calls,
            )

        try:
            executed_detail, executed_rollback = await adapter.perform(action)
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=True, dry_run=False,
                detail=f"EXECUTED — {executed_detail}",
                rollback_hint=executed_rollback or rollback_hint, api_calls=api_calls,
            )
        except Exception as exc:  # noqa: BLE001 - surface execution failures, never crash
            return ActionOutcome(
                action_class=action.action_class, target=action.target,
                executed=False, dry_run=False,
                detail=f"EXECUTION FAILED — {type(exc).__name__}: {exc}",
                rollback_hint=rollback_hint, api_calls=api_calls,
                error=str(exc),
            )

    async def release(self, action: ProposedAction) -> ReleaseOutcome:
        """Undo a containment action Kronagent took. Only ever called for a
        person (approve.py release): nothing in the pipeline releases anything,
        and nothing releases on a timer. Honors dry_run exactly as execution
        does. An adapter or action class with no release says so and gives the
        person the manual steps instead of pretending."""
        adapter = self._adapter(action)
        _, rollback_hint, _ = adapter.plan(action)
        planner = getattr(adapter, "plan_release", None)
        planned = planner(action) if planner is not None else None
        if planned is None:
            return ReleaseOutcome(
                action_class=action.action_class, target=action.target, released=False,
                dry_run=self._settings.dry_run, supported=False,
                detail=(f"Kronagent can't run the release for {action.action_class.value} on "
                        f"{action.provider}. By hand: {rollback_hint}"))
        api_calls, summary = planned
        if self._settings.dry_run:
            return ReleaseOutcome(
                action_class=action.action_class, target=action.target, released=False, dry_run=True,
                detail=f"DRY-RUN — would release: {summary}", api_calls=api_calls)
        try:
            detail = await adapter.release(action)
            return ReleaseOutcome(
                action_class=action.action_class, target=action.target, released=True, dry_run=False,
                detail=f"RELEASED — {detail}", api_calls=api_calls)
        except Exception as exc:  # noqa: BLE001 - surface the failure, never crash
            return ReleaseOutcome(
                action_class=action.action_class, target=action.target, released=False, dry_run=False,
                detail=f"RELEASE FAILED — {type(exc).__name__}: {exc}", api_calls=api_calls, error=str(exc))
