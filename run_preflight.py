#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent pre-flight — is this deployment safe to point at production?

Run it before the first finding arrives, and again from CI or a container
start gate:

    python3 run_preflight.py             # human-readable report
    python3 run_preflight.py --json      # machine-readable
    python3 run_preflight.py --strict    # treat warnings as blocking

Exit codes: 0 ready · 1 warnings worth reading · 2 must be fixed first.

Everything it does is a read. It creates nothing, writes nothing and sends
nothing, so it is safe against a live deployment at any time.
"""

from __future__ import annotations

import argparse
import json
import sys

from kronagent.config import Settings
from kronagent.preflight import PreflightReport, run_preflight

_GLYPH = {"pass": "✓", "warn": "⚠", "fail": "✗"}
_SECTION_TITLES = {
    "safety": "Safety controls",
    "execution": "Execution readiness",
    "providers": "Provider SDKs",
    "storage": "Storage & audit integrity",
    "identity": "Operator identity",
    "governance": "Earn-trust governance",
    "agents": "Agents & backstops",
    "chatops": "Approvals in Slack",
}


def _render(report: PreflightReport, dry_run: bool) -> None:
    print("Kronagent pre-flight")
    print(f"mode: {'DRY-RUN (nothing executes)' if dry_run else 'LIVE EXECUTION ARMED'}")

    for section, title in _SECTION_TITLES.items():
        checks = [c for c in report.checks if c.section == section]
        if not checks:
            continue
        print(f"\n{title}")
        for check in checks:
            print(f"  {_GLYPH[check.status]} {check.name}: {check.detail}")
            if check.fix and check.status != "pass":
                print(f"      fix: {check.fix}")

    counts = report.as_dict()["counts"]
    print(f"\n{counts['pass']} passed, {counts['warn']} warning(s), {counts['fail']} failure(s).")
    if report.failures:
        print("NOT READY — fix the failures above before pointing this at production.")
    elif report.warnings:
        print("Ready, with warnings worth reading.")
    else:
        print("Ready.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Kronagent deployment pre-flight check")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero on warnings too (for a deploy gate)")
    args = parser.parse_args()

    settings = Settings.from_env()
    report = run_preflight(settings)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        _render(report, settings.dry_run)

    if report.failures:
        return 2
    if args.strict and report.warnings:
        return 1
    return 0 if not report.warnings else 1


if __name__ == "__main__":
    sys.exit(main())
