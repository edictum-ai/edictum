"""Regression tests for the fail-closed gate of the v0.18 workflow runner.

The gate fires at collection time inside test_workflow_v018.py, so these
checks cannot live inside that module. Each test spawns the real runner
under pytest as a child process against a temporary fixtures tree and
asserts on the exit status AND the specific rejection reason in the
output — a non-zero exit alone would also pass on any unrelated crash.

With the gate reverted to checking only the directory, the empty-directory
child collects successfully (every parametrize list is empty and the module
skips), exits 0, and these tests go red.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUNNER = "tests/test_conformance/test_workflow_v018.py"
_REQUIRED_MESSAGE = "no workflow-v0.18 fixtures were loaded"


def _run_runner(env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # Strip inherited EDICTUM_* variables so a parent conformance run
    # cannot leak its environment into the child.
    env = {k: v for k, v in os.environ.items() if not k.startswith("EDICTUM_")}
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", _RUNNER],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        # Collection only — a healthy child finishes in seconds; a tight
        # deadline makes a hang diagnosable instead of a five-minute wait.
        timeout=60,
    )


def _empty_v018_root(tmp: Path) -> str:
    (tmp / "fixtures" / "workflow-v0.18").mkdir(parents=True)
    return str(tmp)


def test_required_mode_empty_dir_fails_collection() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-empty-") as tmp:
        result = _run_runner(
            {
                "EDICTUM_SCHEMAS_DIR": _empty_v018_root(Path(tmp)),
                "EDICTUM_CONFORMANCE_REQUIRED": "1",
            }
        )
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE in combined, f"runner output:\n{combined}"


def test_optional_mode_empty_dir_stays_a_skip() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-opt-") as tmp:
        result = _run_runner({"EDICTUM_SCHEMAS_DIR": _empty_v018_root(Path(tmp))})
        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE not in combined, f"runner output:\n{combined}"
