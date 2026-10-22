"""
KRONAGENT_STATE_DIR moves every default state file into one directory — the
container's volume — and an explicit path still wins over it.
"""

from __future__ import annotations

import os

from kronagent.config import Settings
from kronagent.crypto import LocalAsymmetricSigner, get_signer

PATH_VARS = ("KRONAGENT_AUDIT_PATH", "KRONAGENT_APPROVAL_PATH", "KRONAGENT_OUTCOME_PATH",
             "KRONAGENT_ALLOWLIST_PATH", "KRONAGENT_CONNECTION_PATH",
             "KRONAGENT_TRAJECTORY_STATE_PATH", "KRONAGENT_DB_PATH")


def _clean(monkeypatch) -> None:
    for var in PATH_VARS:
        monkeypatch.delenv(var, raising=False)


def test_default_state_files_live_in_the_state_dir(monkeypatch, tmp_path) -> None:
    _clean(monkeypatch)
    monkeypatch.setenv("KRONAGENT_STATE_DIR", str(tmp_path))
    s = Settings.from_env()
    for path in (s.audit_log_path, s.approval_store_path, s.outcome_store_path,
                 s.allowlist_store_path, s.connection_store_path, s.trajectory_state_path):
        assert os.path.dirname(path) == str(tmp_path), path


def test_without_a_state_dir_nothing_moves(monkeypatch) -> None:
    _clean(monkeypatch)
    monkeypatch.delenv("KRONAGENT_STATE_DIR", raising=False)
    s = Settings.from_env()
    assert s.audit_log_path == "kronagent_audit.jsonl"
    assert s.trajectory_state_path == "kronagent_trajectory_halt.json"


def test_an_explicit_path_wins_over_the_state_dir(monkeypatch, tmp_path) -> None:
    _clean(monkeypatch)
    monkeypatch.setenv("KRONAGENT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("KRONAGENT_AUDIT_PATH", "/elsewhere/audit.jsonl")
    assert Settings.from_env().audit_log_path == "/elsewhere/audit.jsonl"


def test_the_signing_key_lives_in_the_state_dir(monkeypatch, tmp_path) -> None:
    """A key in the container's working directory would be regenerated on every
    restart, and no verdict signed before it would verify."""
    _clean(monkeypatch)
    monkeypatch.delenv("KRONAGENT_KMS_KEY_ID", raising=False)
    monkeypatch.setenv("KRONAGENT_STATE_DIR", str(tmp_path))
    signer = get_signer(Settings.from_env())
    assert isinstance(signer, LocalAsymmetricSigner)
    assert (tmp_path / "kronagent_key.pem").exists()
