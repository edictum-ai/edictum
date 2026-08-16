"""Regression tests for the fail-closed gate of the v0.18 workflow runner.

The gate fires at collection time inside test_workflow_v018.py, so these
checks cannot live inside that module. Each test spawns the real runner
under pytest as a child process against a temporary fixtures tree and
asserts on the exit status AND the specific rejection reason in the
output — a non-zero exit alone would also pass on any unrelated crash.

With the gate reverted to checking only the directory, or only the
union of loaded fixtures, the empty-directory and one-suite children
collect successfully, exit 0, and these tests go red.
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
_SUITE_FILES = (
    "wildcard-tools.workflow-v0.18.yaml",
    "terminal-stage.workflow-v0.18.yaml",
    "mcp-result-evidence.workflow-v0.18.yaml",
    "extends-inheritance.workflow-v0.18.yaml",
)


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


def _v018_root(tmp: Path, present: dict[str, str] | None = None) -> str:
    """Write a fixtures tree. ``present`` maps suite filename -> fixture id.

    Omitted names are missing files. That is the truncated-checkout shape.
    """
    d = tmp / "fixtures" / "workflow-v0.18"
    d.mkdir(parents=True)
    for filename, fixture_id in (present or {}).items():
        (d / filename).write_text(f"suite: stub\nfixtures:\n  - id: {fixture_id}\n")
    return str(tmp)


def test_required_mode_empty_dir_fails_collection() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-empty-") as tmp:
        result = _run_runner(
            {
                "EDICTUM_SCHEMAS_DIR": _v018_root(Path(tmp)),
                "EDICTUM_CONFORMANCE_REQUIRED": "1",
            }
        )
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE in combined, f"runner output:\n{combined}"
        assert (
            "empty suites: " + ", ".join(name.removesuffix(".workflow-v0.18.yaml") for name in _SUITE_FILES) in combined
        ), f"runner output:\n{combined}"


def test_required_mode_one_nonempty_suite_fails_collection() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-partial-") as tmp:
        result = _run_runner(
            {
                "EDICTUM_SCHEMAS_DIR": _v018_root(
                    Path(tmp),
                    {_SUITE_FILES[0]: "only-wildcard"},
                ),
                "EDICTUM_CONFORMANCE_REQUIRED": "1",
            }
        )
        combined = result.stdout + result.stderr
        assert result.returncode != 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE in combined, f"runner output:\n{combined}"
        assert "empty suites: terminal-stage, mcp-result-evidence, extends-inheritance" in combined, (
            f"runner output:\n{combined}"
        )
        assert "empty suites: wildcard-tools" not in combined, f"runner output:\n{combined}"


def test_required_mode_all_four_suites_collects() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-full-") as tmp:
        result = _run_runner(
            {
                "EDICTUM_SCHEMAS_DIR": _v018_root(
                    Path(tmp),
                    {name: f"stub-{i}" for i, name in enumerate(_SUITE_FILES)},
                ),
                "EDICTUM_CONFORMANCE_REQUIRED": "1",
            }
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE not in combined, f"runner output:\n{combined}"


def test_optional_mode_empty_dir_stays_a_skip() -> None:
    with tempfile.TemporaryDirectory(prefix="edictum-v018-opt-") as tmp:
        result = _run_runner({"EDICTUM_SCHEMAS_DIR": _v018_root(Path(tmp))})
        combined = result.stdout + result.stderr
        assert result.returncode == 0, f"runner output:\n{combined}"
        assert _REQUIRED_MESSAGE not in combined, f"runner output:\n{combined}"
