"""Tests for Principal Enhancement (Stream B).

Tests cover:
- Principal creation with new fields (role, ticket_ref, claims)
- Principal creation without new fields (backwards compat)
- Frozen dataclass behavior with claims dict
- Envelope propagation of new fields
- Audit event serialization includes new fields
"""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from edictum.audit import AuditEvent, FileAuditSink, StdoutAuditSink
from edictum.envelope import Principal, create_envelope


class TestPrincipalNewFields:
    """Test Principal with the new role, ticket_ref, and claims fields."""

    def test_principal_with_all_new_fields(self):
        p = Principal(
            user_id="alice",
            service_id="svc-1",
            org_id="org-1",
            role="sre",
            ticket_ref="JIRA-1234",
            claims={"department": "platform", "clearance": "high"},
        )
        assert p.user_id == "alice"
        assert p.service_id == "svc-1"
        assert p.org_id == "org-1"
        assert p.role == "sre"
        assert p.ticket_ref == "JIRA-1234"
        assert p.claims == {"department": "platform", "clearance": "high"}

    def test_principal_backwards_compat_no_new_fields(self):
        """Existing code that only uses user_id/service_id/org_id still works."""
        p = Principal(user_id="bob", service_id="svc-2", org_id="org-2")
        assert p.user_id == "bob"
        assert p.role is None
        assert p.ticket_ref is None
        assert p.claims == {}

    def test_principal_defaults(self):
        """All fields are optional with defaults."""
        p = Principal()
        assert p.user_id is None
        assert p.service_id is None
        assert p.org_id is None
        assert p.role is None
        assert p.ticket_ref is None
        assert p.claims == {}

    def test_principal_role_only(self):
        p = Principal(role="admin")
        assert p.role == "admin"
        assert p.user_id is None

    def test_principal_ticket_ref_only(self):
        p = Principal(ticket_ref="INC-5678")
        assert p.ticket_ref == "INC-5678"

    def test_principal_claims_only(self):
        p = Principal(claims={"team": "backend"})
        assert p.claims == {"team": "backend"}


class TestPrincipalFrozen:
    """Test frozen dataclass behavior with claims dict."""

    def test_cannot_reassign_role(self):
        p = Principal(role="sre")
        with pytest.raises(AttributeError):
            p.role = "admin"

    def test_cannot_reassign_ticket_ref(self):
        p = Principal(ticket_ref="JIRA-1")
        with pytest.raises(AttributeError):
            p.ticket_ref = "JIRA-2"

    def test_cannot_reassign_claims_reference(self):
        """The claims dict reference itself is frozen."""
        p = Principal(claims={"k": "v"})
        with pytest.raises(AttributeError):
            p.claims = {"new": "dict"}

    def test_claims_dict_contents_are_technically_mutable(self):
        """Document the known tradeoff: dict contents can be mutated.

        This is by design — frozen dataclass freezes the reference, not
        the dict contents. Callers should treat claims as read-only.
        """
        p = Principal(claims={"k": "v"})
        # This works (known tradeoff, documented in docstring)
        p.claims["k2"] = "v2"
        assert p.claims == {"k": "v", "k2": "v2"}

    def test_empty_claims_instances_are_independent(self):
        """Each Principal gets its own claims dict from default_factory."""
        p1 = Principal()
        p2 = Principal()
        p1.claims["x"] = 1
        assert "x" not in p2.claims


class TestPrincipalAsDict:
    """Test serialization of Principal with new fields."""

    def test_asdict_full(self):
        p = Principal(
            user_id="alice",
            role="sre",
            ticket_ref="JIRA-1234",
            claims={"dept": "platform"},
        )
        d = asdict(p)
        assert d == {
            "user_id": "alice",
            "service_id": None,
            "org_id": None,
            "role": "sre",
            "ticket_ref": "JIRA-1234",
            "claims": {"dept": "platform"},
        }

    def test_asdict_defaults(self):
        p = Principal()
        d = asdict(p)
        assert d["role"] is None
        assert d["ticket_ref"] is None
        assert d["claims"] == {}


class TestEnvelopePropagation:
    """Test that new Principal fields propagate through create_envelope."""

    def test_envelope_with_enhanced_principal(self):
        principal = Principal(
            user_id="arnold",
            role="sre",
            ticket_ref="JIRA-1234",
            claims={"department": "platform"},
        )
        tool_call = create_envelope(
            "TestTool",
            {"key": "value"},
            principal=principal,
        )
        assert tool_call.principal == principal  # deep-copied, not identity
        assert tool_call.principal.role == "sre"
        assert tool_call.principal.ticket_ref == "JIRA-1234"
        assert tool_call.principal.claims == {"department": "platform"}

    def test_envelope_without_principal(self):
        """Backwards compat: tool_call without principal still works."""
        tool_call = create_envelope("TestTool", {"key": "value"})
        assert tool_call.principal is None

    def test_envelope_with_legacy_principal(self):
        """Backwards compat: principal without new fields still works."""
        principal = Principal(user_id="bob")
        tool_call = create_envelope("TestTool", {}, principal=principal)
        assert tool_call.principal.user_id == "bob"
        assert tool_call.principal.role is None
        assert tool_call.principal.ticket_ref is None
        assert tool_call.principal.claims == {}


class TestAuditEventPrincipalSerialization:
    """Test that AuditEvent includes new Principal fields when serialized."""

    def test_audit_event_with_enhanced_principal(self):
        principal_dict = asdict(
            Principal(
                user_id="alice",
                role="sre",
                ticket_ref="JIRA-1234",
                claims={"department": "platform"},
            )
        )
        event = AuditEvent(
            tool_name="TestTool",
            principal=principal_dict,
        )
        assert event.principal["user_id"] == "alice"
        assert event.principal["role"] == "sre"
        assert event.principal["ticket_ref"] == "JIRA-1234"
        assert event.principal["claims"] == {"department": "platform"}

    def test_audit_event_principal_none(self):
        event = AuditEvent(tool_name="TestTool")
        assert event.principal is None

    async def test_stdout_sink_serializes_principal(self, capsys):
        """StdoutAuditSink includes principal fields in JSON output."""
        principal_dict = asdict(
            Principal(
                user_id="alice",
                role="admin",
                claims={"env": "prod"},
            )
        )
        sink = StdoutAuditSink()
        event = AuditEvent(tool_name="TestTool", principal=principal_dict)
        await sink.emit(event)
        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["principal"]["user_id"] == "alice"
        assert data["principal"]["role"] == "admin"
        assert data["principal"]["claims"] == {"env": "prod"}

    async def test_file_sink_serializes_principal(self, tmp_path):
        """FileAuditSink includes principal fields in JSONL output."""
        principal_dict = asdict(
            Principal(
                user_id="bob",
                role="developer",
                ticket_ref="INC-99",
                claims={"team": "backend"},
            )
        )
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(str(path))
        event = AuditEvent(tool_name="TestTool", principal=principal_dict)
        await sink.emit(event)
        data = json.loads(path.read_text().strip())
        assert data["principal"]["user_id"] == "bob"
        assert data["principal"]["role"] == "developer"
        assert data["principal"]["ticket_ref"] == "INC-99"
        assert data["principal"]["claims"] == {"team": "backend"}

    async def test_file_sink_principal_none(self, tmp_path):
        """FileAuditSink handles None principal."""
        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(str(path))
        event = AuditEvent(tool_name="TestTool")
        await sink.emit(event)
        data = json.loads(path.read_text().strip())
        assert data["principal"] is None
