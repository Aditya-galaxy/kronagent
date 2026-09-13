"""
Provider scope — a promotion covers the providers it was earned on.

`block_ip` can be carried out by five providers: an AWS network ACL entry, an
Azure NSG rule, a GCP firewall rule, a Cloudflare edge rule, an on-premises
firewall. The allowlist was keyed by class alone, so one promotion granted
autonomy on all five. The console even labelled the option "block_ip (AWS)"
while the entry it wrote covered Cloudflare, Azure, GCP and on-prem as well.
Thirty quiet days of edge blocks are not evidence about rewriting ACLs in
someone's production VPC.

What is pinned here:
  * the class → provider table matches what the provider modules can do;
  * a shared class cannot be promoted without naming providers, and a
    single-provider class needs no choice;
  * the gate refuses an entry on a provider outside its scope, and says so;
  * renewals keep the scope unless they change it, audited either way;
  * entries written before scoping keep covering everything, and are flagged;
  * every write path — store, CLI, web, console — carries the scope.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from kronagent.allowlist import AllowlistStore, ProviderScopeError, resolve_provider_scope
from kronagent.audit import AuditLog
from kronagent.classification import _ACTION_PROVIDERS, providers_for
from kronagent.config import Settings
from kronagent.policy import PolicyEngine
from kronagent.schemas import ActionClass, ProposedAction

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_the_provider_table_matches_what_each_provider_module_can_do() -> None:
    """Read from the provider modules themselves: every `ActionClass.X` a
    provider's planner proposes or its adapter executes."""
    found: dict[str, set[str]] = {}
    for module in sorted((REPO_ROOT / "kronagent" / "providers").glob("*.py")):
        if module.name == "__init__.py":
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"))
        provider = next(
            node.value.value for node in tree.body
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "PROVIDER"
        )
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "ActionClass"):
                found.setdefault(node.attr, set()).add(provider)

    table = {ac.name: set(providers) for ac, providers in _ACTION_PROVIDERS.items()}
    assert table == found
    assert set(_ACTION_PROVIDERS) == set(ActionClass), "every action class needs providers"
    assert len(providers_for(ActionClass.BLOCK_IP)) > 1, "the case this exists for"


def test_a_single_provider_class_needs_no_choice() -> None:
    assert resolve_provider_scope(ActionClass.ISOLATE_POD, None) == ["kubernetes"]


@pytest.mark.parametrize("providers", [None, [], ["kubernetes"], ["aws", "nowhere"]])
def test_a_shared_class_must_name_real_providers(providers) -> None:
    with pytest.raises(ProviderScopeError):
        resolve_provider_scope(ActionClass.BLOCK_IP, providers)


def test_a_scope_is_deduplicated_and_ordered() -> None:
    assert resolve_provider_scope(ActionClass.BLOCK_IP, ["gcp", "aws", "gcp"]) == ["aws", "gcp"]


@pytest.fixture
def store(tmp_path) -> AllowlistStore:
    return AllowlistStore(str(tmp_path / "allowlist.json"))


async def test_promoting_a_shared_class_without_a_scope_writes_nothing(store, audit_log) -> None:
    with pytest.raises(ProviderScopeError):
        await store.add(ActionClass.BLOCK_IP, by="alice", reason="r", audit=audit_log)
    assert store.list() == []
    assert audit_log.records() == []


def _action(provider: str) -> ProposedAction:
    return ProposedAction(provider=provider, action_class=ActionClass.BLOCK_IP,
                          target="203.0.113.7", rationale="r")


async def test_the_gate_refuses_an_entry_on_a_provider_outside_its_scope(tmp_path) -> None:
    settings = Settings(dry_run=True, allowlist_store_path=str(tmp_path / "al.json"),
                        audit_log_path=str(tmp_path / "audit.jsonl"))
    store = AllowlistStore(settings.allowlist_store_path)
    await store.add(ActionClass.BLOCK_IP, providers=["cloudflare"], by="alice",
                    reason="30 days of clean edge blocks", audit=AuditLog(settings.audit_log_path))
    engine = PolicyEngine(settings, store)

    assert engine.decide(_action("cloudflare"), severity=8.0).disposition == "auto_execute"
    aws = engine.decide(_action("aws"), severity=8.0)
    assert aws.disposition == "requires_approval"
    assert "covers cloudflare only, not aws" in aws.reason


async def test_a_renewal_keeps_its_scope_unless_it_changes_it(store, audit_log) -> None:
    await store.add(ActionClass.BLOCK_IP, providers=["aws"], by="alice", reason="r",
                    audit=audit_log)
    await store.add(ActionClass.BLOCK_IP, by="alice", reason="still applies", audit=audit_log)
    assert store.list()[0].provider_scope == ["aws"]

    await store.add(ActionClass.BLOCK_IP, providers=["aws", "gcp"], by="alice",
                    reason="earned on gcp too", audit=audit_log)
    payload = audit_log.records()[-1]["payload"]
    assert payload["provider_scope"] == ["aws", "gcp"]
    assert payload["previous_provider_scope"] == ["aws"]


async def test_an_entry_from_before_scoping_covers_everything_and_must_scope_to_renew(
        store, audit_log) -> None:
    store._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    for provider in providers_for(ActionClass.BLOCK_IP):
        assert store.evaluate(ActionClass.BLOCK_IP, provider=provider)[0] is True
    with pytest.raises(ProviderScopeError):
        await store.add(ActionClass.BLOCK_IP, by="alice", reason="renew", audit=audit_log)


def test_a_seeded_entry_records_that_it_covers_every_provider(tmp_path) -> None:
    seeded = AllowlistStore(str(tmp_path / "al.json"), seed=frozenset({"block_ip", "isolate_pod"}))
    scopes = {e.action_class: e.provider_scope for e in seeded.list()}
    assert scopes == {"block_ip": sorted(providers_for(ActionClass.BLOCK_IP)),
                      "isolate_pod": ["kubernetes"]}


def _cli(args: list[str], tmp_path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "promote.py"), *args],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
        env={**os.environ, "KRONAGENT_ALLOWLIST_PATH": str(tmp_path / "allowlist.json"),
             "KRONAGENT_AUDIT_PATH": str(tmp_path / "audit.jsonl")},
    )


def test_cli_requires_a_provider_for_a_shared_class_and_flags_unscoped_entries(tmp_path) -> None:
    refused = _cli(["add", "block_ip", "--by", "alice", "--reason", "r"], tmp_path)
    assert refused.returncode == 2
    assert "--provider" in refused.stderr and "cloudflare" in refused.stderr

    ok = _cli(["add", "block_ip", "--by", "alice", "--reason", "r", "--provider", "aws"], tmp_path)
    assert ok.returncode == 0, ok.stderr
    assert "Covers: aws" in ok.stdout

    AllowlistStore(str(tmp_path / "allowlist.json"))._write_all({"block_ip": {
        "action_class": "block_ip", "added_by": "alice", "reason": "r",
        "added_at": "2026-01-01T00:00:00+00:00",
    }})
    review = _cli(["review", "--by", "carol"], tmp_path)
    assert "covers every provider — renew with --provider" in review.stdout


def test_web_promote_requires_and_returns_the_scope(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from kronagent import web

    from kronagent.identity import hash_token

    registry = tmp_path / "operators.json"
    registry.write_text(json.dumps({"alice": {
        "display_name": "Alice", "roles": ["admin"], "token_sha256": hash_token("secret"),
    }}))
    original = (web.settings, web.allowlist_store, web.audit_log)
    web.settings = Settings(dry_run=True, allowlist_store_path=str(tmp_path / "al.json"),
                            audit_log_path=str(tmp_path / "audit.jsonl"),
                            approval_store_path=str(tmp_path / "approvals.json"),
                            operator_registry_path=str(registry))
    web.allowlist_store = AllowlistStore(web.settings.allowlist_store_path)
    web.audit_log = AuditLog(web.settings.audit_log_path)
    try:
        client = TestClient(web.app)
        body = {"action_class": "block_ip", "operator_id": "alice", "token": "secret", "reason": "r"}
        assert client.post("/api/allowlist/promote", json=body).status_code == 400
        res = client.post("/api/allowlist/promote", json={**body, "providers": ["aws"]})
        assert res.status_code == 200, res.text
        assert res.json()["provider_scope"] == ["aws"]
        review = client.get("/api/allowlist/review").json()[0]
        assert review["provider_scope"] == ["aws"]
        assert "cloudflare" in review["providers_available"]
    finally:
        web.settings, web.allowlist_store, web.audit_log = original


def test_the_console_sends_the_provider_its_label_names() -> None:
    """Every promotable option carries the provider its label shows, that
    provider can really carry the class out, and the promote request sends it."""
    html = (REPO_ROOT / "kronagent" / "static" / "index.html").read_text(encoding="utf-8")
    form = html[html.index('id="promote-class"'):]
    form = form[:form.index("</select>")]
    options = re.findall(r'<option value="([a-z_]+)"([^>]*)>([^<]*)</option>', form)
    assert len(options) >= 5
    label_names = {"AWS": "aws", "Kubernetes": "kubernetes", "Azure": "azure", "GCP": "gcp",
                   "Cloudflare": "cloudflare", "On-prem": "onprem"}
    for value, attrs, label in options:
        provider = re.search(r'data-provider="([a-z]+)"', attrs)
        assert provider, f"{value} has no data-provider"
        assert provider.group(1) in providers_for(ActionClass(value)), value
        shown = re.search(r"\(([^)]+)\)\s*$", label)
        assert shown and label_names[shown.group(1)] == provider.group(1), label

    app_js = (REPO_ROOT / "kronagent" / "static" / "app.js").read_text(encoding="utf-8")
    promote = app_js[app_js.index('fetch("/api/allowlist/promote"'):]
    promote = promote[:promote.index("});")]
    assert "providers:" in promote
