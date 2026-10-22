"""
Pre-flight readiness checks.

The load-bearing test here is the one that catches a live-armed deployment with
a missing quarantine target. That misconfiguration is invisible in dry-run —
the unset value renders into the planned API call as a placeholder string and
is never sent — and only surfaces as a failed containment during a real
incident. Everything else in this file exists to keep the report worth reading:
a check that cries wolf gets ignored, and an ignored pre-flight is worse than
none.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.allowlist import AllowlistStore
from kronagent.config import Settings
from kronagent.preflight import run_preflight
from kronagent.schemas import ActionClass

REPO_ROOT = Path(__file__).resolve().parent.parent


def _settings(tmp_path, **overrides) -> Settings:
    base = dict(
        dry_run=True,
        audit_log_path=str(tmp_path / "audit.jsonl"),
        approval_store_path=str(tmp_path / "approvals.json"),
        allowlist_store_path=str(tmp_path / "allowlist.json"),
    )
    base.update(overrides)
    return Settings(**base)


def _by_name(report) -> dict:
    return {c.name: c for c in report.checks}


async def _promote(settings: Settings, action_class: ActionClass, audit_log) -> None:
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(action_class, by="alice", reason="r", audit=audit_log)


# --------------------------------------------------------------------------- #
# The footgun this module exists for
# --------------------------------------------------------------------------- #

async def test_live_execution_without_a_quarantine_group_is_a_failure(tmp_path, audit_log) -> None:
    """The whole point: dry-run OFF plus an unset quarantine SG means the
    containment call goes out malformed, and nothing else in the platform
    would have said so."""
    settings = _settings(tmp_path, dry_run=False, quarantine_nacl_id="acl-1")
    await _promote(settings, ActionClass.ISOLATE_INSTANCE_SG, audit_log)

    report = run_preflight(settings)
    check = _by_name(report)["config:isolate_instance_sg"]

    assert check.status == "fail"
    assert "KRONAGENT_QUARANTINE_SG_ID" in check.detail
    assert "can fire unattended" in check.detail   # it's allowlisted
    assert report.exit_code == 2
    assert not report.as_dict()["ready"]


async def test_the_same_gap_is_only_a_warning_in_dry_run(tmp_path, audit_log) -> None:
    """Nothing can go wrong today, so it must not read like an emergency — but
    it still has to be visible, because it is what breaks on go-live."""
    settings = _settings(tmp_path, dry_run=True)
    await _promote(settings, ActionClass.ISOLATE_INSTANCE_SG, audit_log)

    check = _by_name(run_preflight(settings))["config:isolate_instance_sg"]
    assert check.status == "warn"
    assert "Harmless in dry-run" in check.detail


async def test_an_approval_gated_class_still_fails_when_unconfigured(tmp_path, audit_log) -> None:
    """An approved action executes through exactly the same path as an
    autonomous one, so "it needs approval first" is not mitigation."""
    settings = _settings(tmp_path, dry_run=False, quarantine_security_group_id="sg-1")
    await _promote(settings, ActionClass.DISABLE_ACCESS_KEY, audit_log)  # a different class

    check = _by_name(run_preflight(settings)).get("config:block_ip")
    assert check is not None and check.status == "fail"
    assert "approval-gated" in check.detail


def test_unreachable_providers_are_not_reported(tmp_path) -> None:
    """A pure-AWS deployment must not be told about Azure and on-prem gaps. Seven
    irrelevant lines is how the one that matters gets skipped."""
    settings = _settings(tmp_path, dry_run=False, quarantine_security_group_id="sg-1",
                         quarantine_nacl_id="acl-1")
    names = _by_name(run_preflight(settings))
    assert not [n for n in names if n.startswith("config:")], names.keys()
    assert names["execution_config"].status == "pass"


def test_a_missing_provider_sdk_blocks_a_live_deployment(tmp_path, monkeypatch) -> None:
    """boto3 absent means every AWS containment plans perfectly and raises at
    the moment of execution. Graded by armedness like everything else, and
    monkeypatched rather than asserted against the machine's own packages —
    CI installs the SDK extras in only some jobs."""
    from kronagent import preflight as pf
    monkeypatch.setattr(pf, "_module_available", lambda dotted: False)

    live = _settings(tmp_path, dry_run=False, quarantine_security_group_id="sg-1",
                     quarantine_nacl_id="acl-1")
    assert _by_name(run_preflight(live))["sdk:aws"].status == "fail"

    dry = _settings(tmp_path, quarantine_security_group_id="sg-1",
                    quarantine_nacl_id="acl-1")
    assert _by_name(run_preflight(dry))["sdk:aws"].status == "warn"


def test_provider_sdk_present_passes(tmp_path, monkeypatch) -> None:
    from kronagent import preflight as pf
    monkeypatch.setattr(pf, "_module_available", lambda dotted: True)
    settings = _settings(tmp_path, quarantine_security_group_id="sg-1",
                         quarantine_nacl_id="acl-1")
    assert _by_name(run_preflight(settings))["sdk:aws"].status == "pass"


def test_a_configured_provider_surfaces_its_own_gaps(tmp_path) -> None:
    """Setting one Azure value signals intent to use Azure, so the rest of the
    Azure requirements become relevant."""
    settings = _settings(tmp_path, dry_run=True, azure_subscription_id="sub-1")
    names = _by_name(run_preflight(settings))
    assert "config:isolate_vm_nsg" in names
    assert "config:isolate_host_network" not in names   # on-prem still untouched


# --------------------------------------------------------------------------- #
# Everything else the report covers
# --------------------------------------------------------------------------- #

def test_broken_audit_chain_is_a_failure(tmp_path) -> None:
    """Tamper-evidence is the product's forensic backbone; a broken chain is
    not something to discover during an incident review."""
    path = tmp_path / "audit.jsonl"
    path.write_text('{"_prev": "0", "_hash": "wrong", "record": {"finding_id": "f", '
                    '"stage": "triage", "payload": {}}}\n')
    report = run_preflight(_settings(tmp_path, audit_log_path=str(path)))
    assert _by_name(report)["audit chain"].status == "fail"


def test_unwritable_audit_path_is_a_failure(tmp_path) -> None:
    """An unwritable audit log means actions run with no record of them."""
    settings = _settings(tmp_path, audit_log_path=str(tmp_path / "nope" / "audit.jsonl"))
    assert _by_name(run_preflight(settings))["writable:audit log"].status == "fail"


def test_half_configured_oidc_is_a_failure(tmp_path) -> None:
    """Issuer without audience enforces nothing, which is worse than no OIDC at
    all because it looks configured."""
    settings = _settings(tmp_path, oidc_issuer="https://idp.example.com")
    assert _by_name(run_preflight(settings))["oidc"].status == "fail"


def test_oidc_with_signature_verification_off_is_a_failure(tmp_path) -> None:
    settings = _settings(tmp_path, oidc_issuer="https://idp.example.com",
                         oidc_audience="kronagent", oidc_verify_signature=False)
    check = _by_name(run_preflight(settings))["oidc"]
    assert check.status == "fail"
    assert "self-signed" in check.detail


def test_missing_operator_registry_warns_about_unauthenticated_mode(tmp_path) -> None:
    check = _by_name(run_preflight(_settings(tmp_path)))["operator registry"]
    assert check.status == "warn"
    assert "unauthenticated" in check.detail


def test_disabled_trajectory_guard_fails_when_live(tmp_path) -> None:
    """With dry-run off and no guard, nothing bounds a runaway burst."""
    live = _settings(tmp_path, dry_run=False, trajectory_guard_enabled=False,
                     trajectory_state_path="")
    assert _by_name(run_preflight(live))["trajectory guard"].status == "fail"

    dry = _settings(tmp_path, trajectory_guard_enabled=False, trajectory_state_path="")
    assert _by_name(run_preflight(dry))["trajectory guard"].status == "warn"


def test_kill_switch_engaged_is_surfaced(tmp_path) -> None:
    check = _by_name(run_preflight(_settings(tmp_path, kill_switch=True)))["kill_switch"]
    assert check.status == "warn"
    assert "blocked" in check.detail


async def test_expired_and_untimed_entries_are_flagged(tmp_path, audit_log) -> None:
    settings = _settings(tmp_path)
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.DISABLE_ACCESS_KEY, by="a", reason="r", audit=audit_log)
    store._write_all({
        **store._read_all(),
        "cordon_node": {"action_class": "cordon_node", "promoted_by": "a", "reason": "r",
                        "promoted_at": "2026-01-01T00:00:00+00:00",
                        "expires_at": "2026-02-01T00:00:00+00:00"},
    })

    names = _by_name(run_preflight(settings))
    assert names["allowlist:expired"].status == "warn"
    assert "cordon_node" in names["allowlist:expired"].detail
    assert "disable_access_key" in names["allowlist:no_ttl"].detail


def test_empty_allowlist_is_the_safe_state(tmp_path) -> None:
    check = _by_name(run_preflight(_settings(tmp_path)))["allowlist"]
    assert check.status == "pass"
    assert "requires human approval" in check.detail


def test_preflight_writes_nothing(tmp_path) -> None:
    """Safe to run against production at any time — including the allowlist
    store, which must not be created as a side effect of inspecting it."""
    settings = _settings(tmp_path)
    before = sorted(os.listdir(tmp_path))
    run_preflight(settings)
    assert sorted(os.listdir(tmp_path)) == before


# --------------------------------------------------------------------------- #
# The CLI, driven as a real subprocess — the exit code is the deploy gate
# --------------------------------------------------------------------------- #

def _run(tmp_path, env_extra: dict) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
        "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
        "KRONAGENT_APPROVAL_PATH": str(tmp_path / "approvals.json"),
        "KRONAGENT_OPERATOR_REGISTRY": "",
        "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": "",
        **env_extra,
    }
    return subprocess.run([sys.executable, str(REPO_ROOT / "run_preflight.py")],
                          capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))


@pytest.mark.parametrize("env,expected", [
    ({"KRONAGENT_DRY_RUN": "true"}, 1),      # warnings only
    ({"KRONAGENT_DRY_RUN": "false"}, 1),     # armed, but nothing configured to get wrong
])
def test_cli_exit_codes(tmp_path, env, expected) -> None:
    """No provider configured on purpose: this pins the exit-code contract, not
    which optional SDKs happen to be installed on the machine running it."""
    assert _run(tmp_path, env).returncode == expected


def test_configuring_one_aws_target_surfaces_the_other(tmp_path) -> None:
    """Setting the quarantine SG but not the NACL is a half-provisioned AWS
    deployment: isolate_instance_sg would work and block_ip would not. Going
    live like that is exactly the state this check exists to refuse."""
    result = _run(tmp_path, {"KRONAGENT_DRY_RUN": "false",
                             "KRONAGENT_QUARANTINE_SG_ID": "sg-1"})
    assert result.returncode == 2
    assert "KRONAGENT_QUARANTINE_NACL_ID" in result.stdout


def test_cli_blocks_on_a_real_misconfiguration(tmp_path) -> None:
    result = _run(tmp_path, {"KRONAGENT_DRY_RUN": "false",
                             "KRONAGENT_QUARANTINE_NACL_ID": "acl-1"})
    assert result.returncode == 2
    assert "NOT READY" in result.stdout
    assert "KRONAGENT_QUARANTINE_SG_ID" in result.stdout


def test_cli_json_is_machine_readable(tmp_path) -> None:
    env = {**os.environ, "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
           "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
           "KRONAGENT_OPERATOR_REGISTRY": "", "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": ""}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "run_preflight.py"), "--json"],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))
    payload = json.loads(result.stdout)
    assert set(payload) == {"ready", "exit_code", "counts", "checks"}
    assert all({"name", "status", "detail", "fix", "section"} == set(c) for c in payload["checks"])


def test_cli_strict_treats_warnings_as_blocking(tmp_path) -> None:
    """So a deploy gate can demand a clean report, not merely a survivable one."""
    env = {**os.environ, "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
           "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
           "KRONAGENT_OPERATOR_REGISTRY": "", "KRONAGENT_AUTO_EXECUTE_ALLOWLIST": ""}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "run_preflight.py"), "--strict"],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))
    assert result.returncode == 1


def test_a_bedrock_backend_that_cannot_be_built_warns(tmp_path, monkeypatch) -> None:
    """KRONAGENT_LLM=bedrock without the SDK, a region or credentials degrades
    to deterministic triage; preflight says so instead of claiming Gemini."""
    from kronagent import llm

    def unavailable():
        raise llm.LLMUnavailableError("no region")
    monkeypatch.setenv("KRONAGENT_LLM", "bedrock")
    monkeypatch.setattr(llm, "BedrockTriageClient", unavailable)
    check = _by_name(run_preflight(_settings(tmp_path)))["llm"]
    assert check.status == "warn" and "no region" in check.detail


def test_a_bedrock_backend_names_its_model(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from kronagent import llm
    monkeypatch.setenv("KRONAGENT_LLM", "bedrock")
    monkeypatch.setattr(llm, "BedrockTriageClient", lambda: SimpleNamespace(model="anthropic.claude-opus-5-5"))
    check = _by_name(run_preflight(_settings(tmp_path)))["llm"]
    assert check.status == "pass" and "anthropic.claude-opus-5-5" in check.detail


@pytest.mark.parametrize("token, websockets_present, bot, expected", [
    ("xoxb-wrong-kind", True, "xoxb-1", "fail"),
    ("xapp-1", False, "xoxb-1", "fail"),
    ("xapp-1", True, "", "warn"),
    ("xapp-1", True, "xoxb-1", "pass"),
])
def test_socket_mode_readiness(tmp_path, monkeypatch, token, websockets_present, bot, expected) -> None:
    from kronagent import preflight as pf
    monkeypatch.setattr(pf, "_module_available", lambda dotted: websockets_present)
    settings = _settings(tmp_path, slack_app_token=token, slack_bot_token=bot, slack_channel_id="C1")
    assert _by_name(run_preflight(settings))["slack_socket_mode"].status == expected


def test_no_socket_mode_check_without_an_app_token(tmp_path) -> None:
    assert "slack_socket_mode" not in _by_name(run_preflight(_settings(tmp_path)))
