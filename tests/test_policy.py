"""
Policy engine — the gate that decides whether an action ever runs unattended.

These are the highest-value tests in the suite: a regression here means an
action either executes when it shouldn't (safety incident) or never executes
when it should (product doesn't work). Every test asserts against real
ActionClass values, not synthetic ones, so a change to the classification
table itself is caught.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from kronagent.allowlist import AllowlistStore
from kronagent.config import Settings
from kronagent.policy import PolicyEngine, _ACTION_PROPERTIES
from kronagent.schemas import ActionClass, BlastRadius

from .conftest import make_action


def _iso(**kwargs) -> str:
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).isoformat()

# The classes the policy engine itself claims are safe to ever auto-execute
# (reversible + single-resource + non-destructive). Any class NOT in this set
# must be structurally incapable of auto-executing, regardless of allowlist
# state -- this is the hard safety ceiling the whole earn-trust story rests on.
_EXPECTED_AUTO_ELIGIBLE = {
    ActionClass.DISABLE_ACCESS_KEY,
    ActionClass.ISOLATE_INSTANCE_SG,
    ActionClass.BLOCK_IP,
    ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
    ActionClass.ISOLATE_POD,
    ActionClass.CORDON_NODE,
}
_EXPECTED_NOT_ELIGIBLE = {
    ActionClass.REVOKE_ROLE_SESSIONS,
    ActionClass.TERMINATE_INSTANCE,
    ActionClass.DELETE_POD,
    ActionClass.SCALE_DEPLOYMENT_ZERO,
}


@pytest.fixture
def engine(tmp_path) -> PolicyEngine:
    settings = Settings(allowlist_store_path=str(tmp_path / "allowlist.json"))
    return PolicyEngine(settings, AllowlistStore(settings.allowlist_store_path))


def test_every_action_class_is_classified() -> None:
    """Every action class the platform can propose must have an explicit
    reversible/blast/destructive classification -- an unclassified class
    silently falls back to the safest default, but that's a code smell worth
    catching, not something to rely on."""
    for ac in ActionClass:
        assert ac in _ACTION_PROPERTIES, f"{ac.value} has no policy classification"


@pytest.mark.parametrize("action_class", sorted(_EXPECTED_AUTO_ELIGIBLE, key=lambda a: a.value))
def test_auto_eligible_classes(action_class: ActionClass, engine: PolicyEngine) -> None:
    assert engine.is_auto_eligible(action_class) is True


@pytest.mark.parametrize("action_class", sorted(_EXPECTED_NOT_ELIGIBLE, key=lambda a: a.value))
def test_not_auto_eligible_classes(action_class: ActionClass, engine: PolicyEngine) -> None:
    assert engine.is_auto_eligible(action_class) is False


def test_unknown_action_class_defaults_to_most_restrictive(engine: PolicyEngine) -> None:
    """An action class with no explicit table entry must never be auto-eligible."""
    props = engine._properties("totally_unregistered_action")  # type: ignore[arg-type]
    assert props["reversible"] is False
    assert props["destructive"] is True
    assert props["blast_radius"] == BlastRadius.ACCOUNT


def test_kill_switch_blocks_everything_even_when_allowlisted(tmp_path) -> None:
    settings = Settings(kill_switch=True, allowlist_store_path=str(tmp_path / "al.json"))
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=frozenset({"disable_access_key"}))
    engine = PolicyEngine(settings, allowlist)
    action = make_action(action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = engine.decide(action, severity=9.0)
    assert decision.disposition == "blocked"
    assert "kill switch" in decision.reason


def test_below_severity_threshold_blocks(engine: PolicyEngine) -> None:
    action = make_action(action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = engine.decide(action, severity=1.0)  # default threshold is 4.0
    assert decision.disposition == "blocked"
    assert "below containment threshold" in decision.reason


def test_auto_eligible_but_not_allowlisted_requires_approval(engine: PolicyEngine) -> None:
    action = make_action(action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = engine.decide(action, severity=8.0)
    assert decision.disposition == "requires_approval"
    assert "not yet in the earn-trust allowlist" in decision.reason


def test_auto_eligible_and_allowlisted_auto_executes(tmp_path) -> None:
    settings = Settings(allowlist_store_path=str(tmp_path / "al.json"))
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=frozenset({"disable_access_key"}))
    engine = PolicyEngine(settings, allowlist)
    action = make_action(action_class=ActionClass.DISABLE_ACCESS_KEY)
    decision = engine.decide(action, severity=8.0)
    assert decision.disposition == "auto_execute"


@pytest.mark.parametrize("action_class", sorted(_EXPECTED_NOT_ELIGIBLE, key=lambda a: a.value))
def test_destructive_action_never_auto_executes_even_when_allowlisted(
    action_class: ActionClass, tmp_path
) -> None:
    """The critical safety invariant: an operator promoting a destructive class
    (by mistake or otherwise) must NOT grant it autonomy. The policy engine's
    own classification is the hard ceiling, not the allowlist."""
    settings = Settings(allowlist_store_path=str(tmp_path / "al.json"))
    allowlist = AllowlistStore(settings.allowlist_store_path, seed=frozenset({action_class.value}))
    engine = PolicyEngine(settings, allowlist)
    action = make_action(action_class=action_class)
    decision = engine.decide(action, severity=9.0)
    assert decision.disposition == "requires_approval"
    assert "destructive or wide blast radius" in decision.reason


def test_allowlist_promotion_takes_effect_without_rebuilding_policy_engine(tmp_path) -> None:
    """The whole point of AllowlistStore: a promotion is visible immediately,
    no restart, to a PolicyEngine instance that was already constructed."""
    settings = Settings(allowlist_store_path=str(tmp_path / "al.json"))
    allowlist = AllowlistStore(settings.allowlist_store_path)
    engine = PolicyEngine(settings, allowlist)
    action = make_action(action_class=ActionClass.CORDON_NODE)

    before = engine.decide(action, severity=8.0)
    assert before.disposition == "requires_approval"

    # Promote via the store's own write path, not by rebuilding `engine`.
    data = {"cordon_node": {"action_class": "cordon_node", "added_by": "t", "added_at": "t", "reason": "t"}}
    allowlist._write_all(data)  # exercise the same file the store reads live

    after = engine.decide(action, severity=8.0)
    assert after.disposition == "auto_execute"


def test_expired_allowlist_entry_routes_back_to_approval(tmp_path) -> None:
    """The earn-trust dial has to turn both ways on its own. An entry whose TTL
    has lapsed grants nothing — and the policy engine reaches that verdict from
    the entry itself, with no sweep, cron, or restart in the loop."""
    settings = Settings(allowlist_store_path=str(tmp_path / "al.json"))
    allowlist = AllowlistStore(settings.allowlist_store_path)
    engine = PolicyEngine(settings, allowlist)
    action = make_action(action_class=ActionClass.CORDON_NODE)

    def _promote(expires_at: str) -> None:
        allowlist._write_all({"cordon_node": {
            "action_class": "cordon_node", "added_by": "t", "reason": "t",
            "added_at": _iso(days=-30), "expires_at": expires_at,
        }})

    _promote(_iso(days=30))
    assert engine.decide(action, severity=8.0).disposition == "auto_execute"

    _promote(_iso(days=-1))
    lapsed = engine.decide(action, severity=8.0)
    assert lapsed.disposition == "requires_approval"
    # Says the entry lapsed, not that the class was never promoted — the
    # approver's next move is a renewal decision, not a first promotion.
    assert "expired" in lapsed.reason
    assert "not yet in the earn-trust allowlist" not in lapsed.reason
