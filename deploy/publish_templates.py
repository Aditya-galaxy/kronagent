#!/usr/bin/env python3
"""
Render the deployable IAM artifacts from the one source that defines them.

`deploy/cloudformation/*.json` and `deploy/kronagent-iam-policy.json` describe
the same grant three times over. They were maintained by hand, and they had
drifted four separate ways — a policy name the adapter never writes, an action
nothing calls, a NACL grant covering every ACL in the account while the README
promised it covered one, and two missing read permissions without which
containment could not run at all.

They are generated now. `kronagent/connect.py` is the source; these files are
build output that happens to be committed, because a grant that exists only as
a function's return value is not something a security reviewer can read in a
pull request, and "the customer reads exactly what they are granting" is the
whole premise of splitting observe from contain.

    python3 deploy/publish_templates.py --check    # CI: fail on drift
    python3 deploy/publish_templates.py --write    # regenerate after a change

Publishing to S3 is deliberately not implemented here. No bucket exists, and a
half-written uploader is worse than none: it invites someone to point it at a
bucket without the verification that makes publishing safe (re-fetching each
object anonymously, the way a customer's browser will, and refusing to
overwrite a template someone may already have installed).
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kronagent.aws_stack import render_stack  # noqa: E402
from kronagent.connect import (  # noqa: E402
    AwsConnection,
    Grant,
    _contain_policy,
    render_template,
)

DEPLOY = Path(__file__).resolve().parent

# The placeholders deploy/README.md tells an operator to substitute. Spelled
# loudly rather than left blank: a blank renders a syntactically valid ARN that
# matches nothing, producing a role that installs cleanly and fails only at
# containment time.
PLACEHOLDER_ACCOUNT = "ACCOUNT_ID"
PLACEHOLDER_REGION = "REGION"
PLACEHOLDER_NACL = "QUARANTINE_NACL_ID"
PLACEHOLDER_SG = "QUARANTINE_SG_ID"
# The standalone policy is attached in one account, in one partition, by an
# operator who knows which. Commercial is the right default; GovCloud and China
# operators substitute it along with the other placeholders.
PLACEHOLDER_PARTITION = "aws"

# Only ever used to satisfy AwsConnection's own validation while rendering the
# parameterized form, whose every tenant-specific value is replaced by a
# CloudFormation parameter before it reaches the output.
_RENDER_STUB = AwsConnection(
    tenant_id="template",
    account_id="000000000000",
    region="us-east-1",
    external_id="kronagent-template-placeholder-external-id",
    observe_role_arn="arn:aws:iam::000000000000:role/KronagentObserveRole",
)


def artifacts() -> dict[Path, dict]:
    """Every generated file, mapped to the object it should contain."""
    return {
        DEPLOY / "cloudformation" / "kronagent-observe-role.json": render_template(
            _RENDER_STUB, Grant.OBSERVE,
            kronagent_account_id="${KronagentAccountId}", parameterized=True),
        DEPLOY / "cloudformation" / "kronagent-contain-role.json": render_template(
            _RENDER_STUB, Grant.CONTAIN,
            kronagent_account_id="${KronagentAccountId}", parameterized=True),
        # Kronagent running inside the customer's own account (kronagent/aws_stack.py).
        DEPLOY / "cloudformation" / "kronagent-in-account.json": render_stack(),
        # The standalone policy an operator attaches by hand per deploy/README.md
        # §3. It is the one artifact that includes terminate, because it is not
        # a grant a customer is asked to review — it is one an operator writes
        # for their own account.
        DEPLOY / "kronagent-iam-policy.json": _contain_policy(
            PLACEHOLDER_ACCOUNT, PLACEHOLDER_REGION, PLACEHOLDER_NACL,
            PLACEHOLDER_SG, include_terminate=True,
            partition=PLACEHOLDER_PARTITION),
    }


def _serialize(obj: dict) -> str:
    return json.dumps(obj, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="fail if any committed file differs from the renderer")
    mode.add_argument("--write", action="store_true",
                      help="regenerate the committed files")
    args = ap.parse_args()

    drifted = 0
    for path, obj in artifacts().items():
        expected = _serialize(obj)
        actual = path.read_text(encoding="utf-8") if path.exists() else ""
        rel = path.relative_to(DEPLOY.parent)

        if expected == actual:
            print(f"  ok       {rel}")
            continue

        drifted += 1
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
            print(f"  written  {rel}")
        else:
            print(f"  DRIFTED  {rel}")
            for line in difflib.unified_diff(
                    actual.splitlines(), expected.splitlines(),
                    fromfile=f"{rel} (committed)", tofile=f"{rel} (rendered)",
                    lineterm="", n=2):
                print(f"    {line}")

    if args.check and drifted:
        print(f"\n{drifted} generated file(s) do not match kronagent/connect.py.\n"
              f"These are build output. Edit the policy functions in connect.py "
              f"and run `python3 deploy/publish_templates.py --write` — a hand "
              f"edit here is how the contain role came to pin an inline policy "
              f"name the adapter never writes.")
        return 1

    print(f"\n{'regenerated' if args.write else 'checked'} "
          f"{len(artifacts())} artifact(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
