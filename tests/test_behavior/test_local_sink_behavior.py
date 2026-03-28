"""Integration tests for local_sink — present on every construction path, receives pipeline events."""

from __future__ import annotations

import pytest

from edictum import AuditAction, Edictum
from edictum.audit import CollectingAuditSink
from tests.conftest import CapturingAuditSink, NullAuditSink

MINIMAL_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: allow-all
    type: pre
    tool: "*"
    when:
      tool_name:
        equals: "__never_matches__"
    then:
      action: block
      message: "never fires"
"""


@pytest.fixture()
def yaml_path(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(MINIMAL_YAML)
    return p


class TestLocalSinkPresence:
    def test_local_sink_always_present_init(self):
        guard = Edictum(audit_sink=NullAuditSink())
        assert isinstance(guard.local_sink, CollectingAuditSink)

    def test_local_sink_always_present_from_yaml(self, yaml_path):
        guard = Edictum.from_yaml(str(yaml_path), audit_sink=NullAuditSink())
        assert isinstance(guard.local_sink, CollectingAuditSink)

    def test_local_sink_always_present_from_template(self):
        guard = Edictum.from_template("file-agent", audit_sink=NullAuditSink())
        assert isinstance(guard.local_sink, CollectingAuditSink)

    def test_local_sink_always_present_from_multiple(self):
        g1 = Edictum(audit_sink=NullAuditSink())
        g2 = Edictum(audit_sink=NullAuditSink())
        merged = Edictum.from_multiple([g1, g2])
        assert isinstance(merged.local_sink, CollectingAuditSink)
        # Merged guard gets its own local_sink, distinct from g1/g2
        assert merged.local_sink is not g1.local_sink
        assert merged.local_sink is not g2.local_sink


class TestLocalSinkReceivesEvents:
    async def test_local_sink_receives_events_local_mode(self):
        guard = Edictum(audit_sink=NullAuditSink())
        await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

        events = guard.local_sink.events
        assert len(events) >= 2  # pre + post audit events
        actions = {e.action for e in events}
        assert AuditAction.CALL_ALLOWED in actions

    async def test_local_sink_and_user_sink_both_receive(self):
        user_sink = CapturingAuditSink()
        guard = Edictum(audit_sink=user_sink)
        await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

        assert len(guard.local_sink.events) >= 2
        assert len(user_sink.events) >= 2
        assert len(guard.local_sink.events) == len(user_sink.events)

    def test_none_defaults_to_local_sink_only(self):
        guard = Edictum()
        assert guard.audit_sink is guard.local_sink
        assert isinstance(guard.audit_sink, CollectingAuditSink)

    async def test_local_sink_mark_works_through_pipeline(self):
        guard = Edictum(audit_sink=NullAuditSink())
        m = guard.local_sink.mark()
        await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

        window = guard.local_sink.since_mark(m)
        assert len(window) >= 2
        assert all(e.tool_name == "read_file" for e in window)
