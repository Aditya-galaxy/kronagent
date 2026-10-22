#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent operator-registry admin CLI — bootstrap and manage the identity registry
that gates approvals and governance (see kronagent/identity.py).

Tokens are never stored in the clear: `add` takes a token (flag or prompt) and
persists only its SHA-256. Point the platform at the registry with
KRONAGENT_OPERATOR_REGISTRY (or Settings.operator_registry_path) to switch the
approval/governance CLIs into authenticated, RBAC-enforced mode.

    python3 operators.py add alice --name "Alice Ng" --roles admin --token s3cr3t
    python3 operators.py add bob   --name "Bob Lee"  --roles approver           # prompts for token
    python3 operators.py list
    python3 operators.py disable bob
    python3 operators.py remove bob

Roles: viewer (read), approver (read + approve/deny), admin (+ promote/demote).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile

from kronagent.config import Settings
from kronagent.identity import ALL_TENANTS, DEFAULT_TENANT, hash_token, known_roles


def _registry_path(args: argparse.Namespace) -> str:
    settings = Settings.from_env()
    return (args.registry or settings.operator_registry_path
            or os.path.join(settings.state_dir, "kronagent_operators.json"))


def _load(path: str) -> dict[str, dict]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return {}


def _save(path: str, data: dict[str, dict]) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def cmd_add(args: argparse.Namespace) -> int:
    roles = [r.strip() for r in args.roles.split(",") if r.strip()]
    unknown = [r for r in roles if r not in known_roles()]
    if unknown:
        print(f"Unknown role(s): {unknown}. Valid: {known_roles()}", file=sys.stderr)
        return 2
    token = args.token or getpass.getpass(f"Token for operator '{args.operator_id}': ")
    if not token:
        print("A token is required.", file=sys.stderr)
        return 2

    # Tenants answer "whose data", where roles answer "what may they do". An
    # omitted --tenants means the default tenant only, never all of them.
    tenants = [t.strip() for t in (args.tenants or "").split(",") if t.strip()]

    path = _registry_path(args)
    data = _load(path)
    data[args.operator_id] = {
        "display_name": args.name or args.operator_id,
        "roles": roles,
        "token_sha256": hash_token(token),
        "active": True,
        "tenants": tenants,
    }
    _save(path, data)
    scope = ", ".join(tenants) if tenants else DEFAULT_TENANT
    print(f"Registered operator '{args.operator_id}' ({', '.join(roles)}) in {path}.")
    print(f"Tenant scope: {scope}")
    if ALL_TENANTS in tenants:
        print(f"  ⚠ '{ALL_TENANTS}' grants access to EVERY tenant's incidents and "
              f"containment decisions.")
    print("Only the token hash was stored; keep the token itself safe.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    path = _registry_path(args)
    data = _load(path)
    if not data:
        print(f"No operators registered in {path}.")
        return 0
    print(f"Operators in {path}:")
    for oid, rec in sorted(data.items()):
        status = "" if rec.get("active", True) else "  [disabled]"
        scope = ", ".join(rec.get("tenants") or [DEFAULT_TENANT])
        print(f"  {oid:16} {', '.join(rec.get('roles', [])) or 'no roles':24} "
              f"tenants={scope:20} {rec.get('display_name', '')}{status}")
    return 0


def _set_active(args: argparse.Namespace, active: bool) -> int:
    path = _registry_path(args)
    data = _load(path)
    if args.operator_id not in data:
        print(f"No such operator: {args.operator_id}", file=sys.stderr)
        return 2
    data[args.operator_id]["active"] = active
    _save(path, data)
    print(f"Operator '{args.operator_id}' {'enabled' if active else 'disabled'}.")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    path = _registry_path(args)
    data = _load(path)
    if data.pop(args.operator_id, None) is None:
        print(f"No such operator: {args.operator_id}", file=sys.stderr)
        return 2
    _save(path, data)
    print(f"Removed operator '{args.operator_id}'.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Kronagent operator-registry admin")
    parser.add_argument("--registry", help="registry path (default: KRONAGENT_OPERATOR_REGISTRY or kronagent_operators.json)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="add or replace an operator")
    p_add.add_argument("operator_id")
    p_add.add_argument("--name", help="display name")
    p_add.add_argument("--roles", required=True, help="comma-separated: viewer,approver,admin")
    p_add.add_argument("--token", help="auth token (omit to be prompted; never stored in clear)")
    p_add.add_argument("--tenants",
                       help=f"comma-separated tenants this operator may act on. "
                            f"Omit for '{DEFAULT_TENANT}' only; '{ALL_TENANTS}' grants every tenant.")

    sub.add_parser("list", help="list registered operators")

    p_dis = sub.add_parser("disable", help="deactivate an operator (keeps the record)")
    p_dis.add_argument("operator_id")
    p_en = sub.add_parser("enable", help="reactivate an operator")
    p_en.add_argument("operator_id")

    p_rm = sub.add_parser("remove", help="delete an operator")
    p_rm.add_argument("operator_id")

    args = parser.parse_args()
    if args.command == "add":
        return cmd_add(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "disable":
        return _set_active(args, False)
    if args.command == "enable":
        return _set_active(args, True)
    if args.command == "remove":
        return cmd_remove(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
