#!/usr/bin/env python3
"""
Render the weekly shadow-mode digest for one tenant.

    python3 run_digest.py [--tenant T] [--days 7] [--json] [--out PATH]

Prints markdown by default. It sends nothing: delivering a digest to a customer
is a decision for whoever runs this, not something a report generator should
do on its own.

Exit code 1 when the digest carries an alert — a broken audit chain, an
executed containment, a week with no findings, a degrading approval queue — so
it can run from cron and page someone instead of being filed unread.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from kronagent.approvals import ApprovalStore
from kronagent.audit import AuditLog
from kronagent.config import Settings
from kronagent.digest import build_digest, render_markdown
from kronagent.orchestrator import get_tenant_path
from kronagent.outcomes import OutcomeStore


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive number of days, got {value}")
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kronagent weekly shadow-mode digest")
    ap.add_argument("--tenant", default="default")
    ap.add_argument("--days", type=_positive_int, default=7)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write to this file instead of stdout")
    args = ap.parse_args(argv)

    settings = Settings.from_env()
    audit_path = get_tenant_path(settings.audit_log_path, args.tenant)
    digest = build_digest(
        args.tenant,
        AuditLog.read_records(audit_path),
        ApprovalStore(get_tenant_path(settings.approval_store_path, args.tenant)).list(),
        OutcomeStore(get_tenant_path(settings.outcome_store_path, args.tenant)).list(),
        now=datetime.now(timezone.utc), days=args.days, dry_run=settings.dry_run,
        chain=AuditLog.verify(audit_path), confirm_within=settings.confirm_within,
    )
    text = json.dumps(digest.model_dump(), indent=2) if args.json else render_markdown(digest)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 1 if digest.alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
