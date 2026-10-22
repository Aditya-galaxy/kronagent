"""
Every kronagent-* command the AWS guide tells a customer to run must exist in
the installed package. outcome.py and run_digest.py were once missing from
it, so the image could not run the shadow-mode scorecard the guide relies on.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = set(tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"])
# A command is a kronagent-* word at the start of a code span, a code-block
# line, or an ECS Exec --command.
COMMAND = re.compile(r'(?:`|^|--command ")\s*(kronagent-[a-z-]+)', re.M)


# deploy/README.md names many kronagent-* resources (roles, queues, policies)
# in code spans, so only what it runs through ECS Exec is checked there.
EXEC_COMMAND = re.compile(r'--command "\s*(kronagent-[a-z-]+)')


def test_every_command_in_the_aws_guide_is_installed() -> None:
    for doc, pattern in (("docs/deploy-aws.md", COMMAND), ("deploy/slack/README.md", COMMAND),
                         ("deploy/README.md", EXEC_COMMAND)):
        named = set(pattern.findall((REPO / doc).read_text()))
        assert named, f"{doc}: the pattern found no commands; it has gone stale"
        assert named <= SCRIPTS, f"{doc} names commands the package doesn't install: {sorted(named - SCRIPTS)}"


def test_every_console_script_module_is_packaged() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text())
    modules = set(project["tool"]["setuptools"]["py-modules"])
    for name, target in project["project"]["scripts"].items():
        module = target.split(":")[0]
        assert module in modules, f"{name} points at {module}, which isn't in py-modules"
