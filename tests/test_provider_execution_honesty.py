"""
No provider may report a containment it did not perform.

This is the third instance of one meta-problem: a defect fixed in one provider
reappearing in the next one added. `gcp.py` reported success without calling
GCP; that was fixed, and then `cloudflare.py` shipped with exactly the same
shape — `perform()` returning `plan()`'s summary string, never touching the API:

    executed: True | error: None
    detail  : EXECUTED — block remote IP 185.220.101.7 on Cloudflare global edge
              network firewall

Which goes into the hash-chained audit log as signed compliance evidence, while
the address stays reachable.

It matters more than a missing feature because it attacks the one thing the
product sells — a defensible audit trail. An absent capability gets noticed. A
falsely reported one does not, which is precisely why it needs a test rather
than a code review.

**The invariant.** With no credentials and no control plane configured, no
adapter may return success from `perform()`. A real implementation cannot
succeed in that state — it raises on a missing credential, an unreachable
endpoint, or an unconfigured target. Only a stub that fabricates a result can
return cleanly, so "returned successfully with nothing configured" identifies
the defect exactly.

A call that is still in flight when the timeout expires counts as passing: it
means the adapter really was reaching for the network, which is the honest
behaviour this test exists to require.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio

import pytest

from kronagent.config import Settings
from kronagent.providers import PLANNERS, build_containment_adapters
from kronagent.schemas import ActionClass, ProposedAction

# One representative action per provider — the one an attacker would most want
# falsely reported as done.
_PROBE: dict[str, ActionClass] = {
    "aws": ActionClass.DISABLE_ACCESS_KEY,
    "azure": ActionClass.DEALLOCATE_VM,
    "gcp": ActionClass.DISABLE_SERVICE_ACCOUNT_KEY,
    "kubernetes": ActionClass.ISOLATE_POD,
    "onprem": ActionClass.ISOLATE_HOST_NETWORK,
    "cloudflare": ActionClass.BLOCK_IP,
}


def test_probe_table_covers_every_registered_provider() -> None:
    """A provider absent from the table would silently skip the invariant — the
    same way a new provider silently skipped the fix twice already."""
    assert set(_PROBE) == set(PLANNERS), (
        f"providers not covered by the execution-honesty invariant: "
        f"{set(PLANNERS) - set(_PROBE)}"
    )


@pytest.mark.parametrize("provider", sorted(_PROBE))
async def test_no_adapter_reports_success_without_being_configured(provider) -> None:
    adapters = build_containment_adapters(Settings())
    adapter = adapters[provider]
    action = ProposedAction(
        provider=provider, action_class=_PROBE[provider],
        target="probe-target", rationale="execution-honesty probe",
        parameters={"resource_group": "", "hostname": "probe-host", "namespace": "default"},
    )

    try:
        result = await asyncio.wait_for(adapter.perform(action), timeout=10.0)
    except asyncio.TimeoutError:
        return  # still reaching for the network: honest
    except Exception:
        return  # refused or failed: honest
    pytest.fail(
        f"{provider}: perform() returned {result!r} with nothing configured. "
        f"A real implementation cannot succeed without credentials, so this "
        f"adapter is fabricating a result — the executor will record "
        f"executed=True and the audit log will certify a containment that "
        f"never happened. Raise NotImplementedError instead (see gcp.py / "
        f"cloudflare.py for the pattern)."
    )


@pytest.mark.parametrize("provider", sorted(_PROBE))
def test_planning_still_works_for_every_provider(provider) -> None:
    """The converse guard: refusing to execute must not degrade planning, which
    is what dry-run and the approval queue show an operator."""
    adapters = build_containment_adapters(Settings())
    calls, rollback, detail = adapters[provider].plan(ProposedAction(
        provider=provider, action_class=_PROBE[provider],
        target="probe-target", rationale="plan probe",
    ))
    assert calls and rollback and detail


def test_simulating_adapters_never_ship_enabled() -> None:
    """Adapters that keep an in-memory simulation for tests must default it off,
    or the defect returns through configuration rather than code."""
    for provider, adapter in build_containment_adapters(Settings()).items():
        simulate = getattr(adapter, "_simulate", False)
        assert simulate is False, f"{provider} ships with simulation enabled"
