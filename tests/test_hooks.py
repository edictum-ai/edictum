"""Tests for HookDecision and HookResult."""

from __future__ import annotations

from edictum.hooks import HookDecision, HookResult


class TestHookDecision:
    def test_allow(self):
        d = HookDecision.allow()
        assert d.result == HookResult.ALLOW
        assert d.reason is None

    def test_deny(self):
        d = HookDecision.deny("not allowed")
        assert d.result == HookResult.DENY
        assert d.reason == "not allowed"

    def test_deny_truncation(self):
        long_reason = "x" * 600
        d = HookDecision.deny(long_reason)
        assert len(d.reason) == 500
        assert d.reason.endswith("...")

    def test_deny_exact_500(self):
        reason = "x" * 500
        d = HookDecision.deny(reason)
        assert d.reason == reason
        assert len(d.reason) == 500

    def test_deny_501(self):
        reason = "x" * 501
        d = HookDecision.deny(reason)
        assert len(d.reason) == 500
        assert d.reason.endswith("...")


class TestHookResult:
    def test_values(self):
        assert HookResult.ALLOW.value == "allow"
        assert HookResult.DENY.value == "block"
