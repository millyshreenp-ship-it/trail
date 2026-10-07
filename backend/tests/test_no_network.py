import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from app.research.guards import NetworkDisabled, assert_no_forbidden_source, network_disabled


ROOT = Path(__file__).resolve().parents[2]


def test_network_guard_blocks_connections_and_restores_socket():
    original = socket.socket
    with network_disabled():
        with pytest.raises(NetworkDisabled):
            socket.socket()
    assert socket.socket is original


def test_research_smoke_does_not_observe_credential_environment(tmp_path):
    smoke = ROOT / "research" / "kaggle" / "smoke.py"
    env = dict(os.environ)
    env["KAGGLE_API_TOKEN"] = "sentinel-must-not-appear"
    result = subprocess.run(
        [sys.executable, str(smoke), "--out", str(tmp_path)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "sentinel-must-not-appear" not in result.stdout
    assert (tmp_path / "metrics.json").exists()


def test_smoke_source_has_no_upload_or_credential_path():
    smoke = ROOT / "research" / "kaggle" / "smoke.py"
    assert_no_forbidden_source([smoke])
