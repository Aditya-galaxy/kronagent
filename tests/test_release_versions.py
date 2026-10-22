"""
One version, everywhere a customer pulls the image from. The release workflow
publishes ghcr.io/aditya-galaxy/kronagent:<pyproject version>; the AWS stack
and the Helm chart must ask for exactly that, or a fresh install pulls an image
that was never published (or an older one than the code describes).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from kronagent.aws_stack import DEFAULT_IMAGE

REPO = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
IMAGE = "ghcr.io/aditya-galaxy/kronagent"


def test_the_aws_stack_runs_this_version() -> None:
    assert DEFAULT_IMAGE == f"{IMAGE}:{VERSION}"


def test_the_helm_chart_runs_this_version() -> None:
    values = (REPO / "deploy/helm/kronagent/values.yaml").read_text()
    assert f"repository: {IMAGE}" in values
    assert re.search(rf'^\s*tag:\s*"{re.escape(VERSION)}"', values, re.M)
    chart = (REPO / "deploy/helm/kronagent/Chart.yaml").read_text()
    assert f'appVersion: "{VERSION}"' in chart


def test_the_release_workflow_publishes_where_they_pull_from() -> None:
    workflow = (REPO / ".github/workflows/release.yml").read_text()
    assert f"IMAGE: {IMAGE}" in workflow
    extras = re.search(r"^\s*EXTRAS:\s*(\S+)", workflow, re.M).group(1).split(",")
    assert {"aws", "bedrock", "slack"} <= set(extras)
