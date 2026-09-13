"""
Shared fixtures for the Kronagent regression suite.

Every stateful fixture (audit log, allowlist, approvals) is rooted in
`tmp_path` so tests never touch the real `kronagent_*.json*` runtime files and
tests never see each other's state.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from kronagent.allowlist import AllowlistStore
from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.schemas import PolicyDecision, ProposedAction

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        dry_run=True,
        kill_switch=False,
        audit_log_path=str(tmp_path / "audit.jsonl"),
        approval_store_path=str(tmp_path / "approvals.json"),
        allowlist_store_path=str(tmp_path / "allowlist.json"),
    )


@pytest.fixture
def audit_log(settings) -> AuditLog:
    return AuditLog(settings.audit_log_path)


@pytest.fixture
def allowlist_store(settings) -> AllowlistStore:
    return AllowlistStore(settings.allowlist_store_path)


@pytest.fixture
def approval_store(settings) -> ApprovalStore:
    return ApprovalStore(settings.approval_store_path)


@pytest.fixture
def guardduty_findings() -> list[dict]:
    return json.loads((SAMPLES_DIR / "guardduty_findings.json").read_text())


@pytest.fixture
def k8s_audit_events() -> list[dict]:
    return json.loads((SAMPLES_DIR / "k8s_audit_events.json").read_text())


class FakeContainmentAdapter:
    """A ContainmentAdapter double: `plan()` is a fixed, deterministic stub;
    `perform()` records every call and can be configured to fail. Used to test
    ContainmentExecutor and the orchestrator without touching boto3/kubernetes."""

    def __init__(self, provider: str = "fake", *, raise_on_perform: Optional[Exception] = None) -> None:
        self.provider = provider
        self.raise_on_perform = raise_on_perform
        self.perform_calls: list[ProposedAction] = []

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        return ([f"fake.call({action.target})"], f"fake.rollback({action.target})", f"fake plan for {action.target}")

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        self.perform_calls.append(action)
        if self.raise_on_perform is not None:
            raise self.raise_on_perform
        return (f"fake executed {action.target}", f"fake rollback for {action.target}")


def make_action(
    *, provider: Optional[str] = None, action_class, target: str = "target-1",
    rationale: str = "test rationale", parameters: Optional[dict] = None,
) -> ProposedAction:
    # Default to a provider that can actually carry the class out: allowlist
    # entries are scoped to providers, so an action on a made-up one would be
    # refused for reasons no test meant to exercise.
    if provider is None:
        from kronagent.classification import providers_for
        provider = min(providers_for(action_class), default="fake")
    return ProposedAction(
        provider=provider, action_class=action_class, target=target,
        rationale=rationale, parameters=parameters or {},
    )


def make_decision(
    *, action_class, disposition: str, reversible: bool = True,
    blast_radius="single_resource", reason: str = "test reason",
) -> PolicyDecision:
    from kronagent.schemas import BlastRadius
    return PolicyDecision(
        action_class=action_class, disposition=disposition, reason=reason,
        reversible=reversible,
        blast_radius=BlastRadius(blast_radius) if isinstance(blast_radius, str) else blast_radius,
    )
