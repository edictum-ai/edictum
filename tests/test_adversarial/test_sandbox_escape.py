"""Adversarial tests for sandbox path resolution."""

from __future__ import annotations

import os

import pytest

from edictum.envelope import create_envelope
from edictum.yaml_engine.compiler import _compile_sandbox, _extract_paths

pytestmark = pytest.mark.security


@pytest.fixture
def sandbox_tmpdir(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "safe.txt").write_text("safe content")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (allowed / "escape").symlink_to(outside)

    (allowed / "chain_b").symlink_to(outside)
    (allowed / "chain_a").symlink_to(allowed / "chain_b")

    return {
        "allowed": str(allowed),
        "safe_file": str(allowed / "safe.txt"),
        "escape_path": str(allowed / "escape" / "secret.txt"),
        "chain_path": str(allowed / "chain_a" / "secret.txt"),
        "outside": str(outside),
    }


class TestSymlinkEscape:
    def test_symlink_inside_allowed_pointing_outside(self, sandbox_tmpdir):
        envelope = create_envelope("Read", {"path": sandbox_tmpdir["escape_path"]})
        paths = _extract_paths(envelope)
        for p in paths:
            assert not p.startswith(sandbox_tmpdir["allowed"])

    def test_symlink_chain_resolved(self, sandbox_tmpdir):
        envelope = create_envelope("Read", {"path": sandbox_tmpdir["chain_path"]})
        paths = _extract_paths(envelope)
        for p in paths:
            assert not p.startswith(sandbox_tmpdir["allowed"])

    def test_normal_file_still_allowed(self, sandbox_tmpdir):
        envelope = create_envelope("Read", {"path": sandbox_tmpdir["safe_file"]})
        paths = _extract_paths(envelope)
        for p in paths:
            assert p.startswith(sandbox_tmpdir["allowed"])

    def test_dotdot_still_denied(self, sandbox_tmpdir):
        escape = os.path.join(sandbox_tmpdir["allowed"], "..", "outside", "secret.txt")
        envelope = create_envelope("Read", {"path": escape})
        paths = _extract_paths(envelope)
        for p in paths:
            assert not p.startswith(sandbox_tmpdir["allowed"])

    def test_nonexistent_path_no_crash(self):
        envelope = create_envelope("Read", {"path": "/tmp/does/not/exist/file.txt"})
        paths = _extract_paths(envelope)
        assert len(paths) >= 1


class TestSandboxContractWithSymlinks:
    def test_sandbox_denies_symlink_escape(self, sandbox_tmpdir):
        contract = {
            "id": "test-sandbox",
            "type": "sandbox",
            "tool": "Read",
            "within": [sandbox_tmpdir["allowed"]],
            "message": "Access denied.",
        }
        sandbox_fn = _compile_sandbox(contract, "enforce")
        envelope = create_envelope("Read", {"path": sandbox_tmpdir["escape_path"]})
        verdict = sandbox_fn(envelope)
        assert not verdict.passed

    def test_sandbox_allows_normal_file(self, sandbox_tmpdir):
        contract = {
            "id": "test-sandbox",
            "type": "sandbox",
            "tool": "Read",
            "within": [sandbox_tmpdir["allowed"]],
            "message": "Access denied.",
        }
        sandbox_fn = _compile_sandbox(contract, "enforce")
        envelope = create_envelope("Read", {"path": sandbox_tmpdir["safe_file"]})
        verdict = sandbox_fn(envelope)
        assert verdict.passed
