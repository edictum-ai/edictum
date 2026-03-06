"""Behavior tests for CollectingAuditSink — mark/since_mark, eviction, overflow, clear, filter."""

from __future__ import annotations

import pytest

from edictum.audit import AuditAction, AuditEvent, CollectingAuditSink, MarkEvictedError


def _make_event(
    action: AuditAction = AuditAction.CALL_ALLOWED,
    tool_name: str = "TestTool",
) -> AuditEvent:
    return AuditEvent(action=action, tool_name=tool_name)


class TestEmitAndQuery:
    async def test_emit_collects_events(self):
        sink = CollectingAuditSink()
        for _ in range(3):
            await sink.emit(_make_event())
        assert len(sink.events) == 3

    async def test_filter_by_action(self):
        sink = CollectingAuditSink()
        await sink.emit(_make_event(action=AuditAction.CALL_ALLOWED))
        await sink.emit(_make_event(action=AuditAction.CALL_DENIED))
        await sink.emit(_make_event(action=AuditAction.CALL_ALLOWED))

        denied = sink.filter(AuditAction.CALL_DENIED)
        assert len(denied) == 1
        assert denied[0].action == AuditAction.CALL_DENIED

    async def test_last_returns_most_recent(self):
        sink = CollectingAuditSink()
        for i in range(3):
            await sink.emit(_make_event(tool_name=f"tool_{i}"))
        assert sink.last().tool_name == "tool_2"

    async def test_last_raises_on_empty(self):
        sink = CollectingAuditSink()
        with pytest.raises(IndexError):
            sink.last()


class TestMarkAndWindow:
    async def test_mark_returns_current_position(self):
        sink = CollectingAuditSink()
        assert sink.mark() == 0
        await sink.emit(_make_event())
        await sink.emit(_make_event())
        assert sink.mark() == 2

    async def test_since_mark_returns_window(self):
        sink = CollectingAuditSink()
        await sink.emit(_make_event(tool_name="before_1"))
        await sink.emit(_make_event(tool_name="before_2"))
        m = sink.mark()
        await sink.emit(_make_event(tool_name="after_1"))
        await sink.emit(_make_event(tool_name="after_2"))
        await sink.emit(_make_event(tool_name="after_3"))

        window = sink.since_mark(m)
        assert len(window) == 3
        assert [e.tool_name for e in window] == ["after_1", "after_2", "after_3"]

    async def test_since_mark_raises_on_eviction(self):
        sink = CollectingAuditSink(max_events=5)
        for _ in range(10):
            await sink.emit(_make_event())
        with pytest.raises(MarkEvictedError):
            sink.since_mark(0)

    async def test_since_mark_valid_after_partial_eviction(self):
        sink = CollectingAuditSink(max_events=5)
        for _ in range(7):
            await sink.emit(_make_event())
        # Buffer now holds events 2-6 (indices). Total emitted = 7, evicted = 2.
        m = sink.mark()  # m = 7
        for _ in range(3):
            await sink.emit(_make_event())
        # Total emitted = 10, buffer holds events 5-9, evicted = 5.
        # m=7 >= evicted=5, so since_mark should work.
        window = sink.since_mark(m)
        assert len(window) == 3

    async def test_since_mark_rejects_future_mark(self):
        sink = CollectingAuditSink()
        await sink.emit(_make_event())
        with pytest.raises(ValueError, match="ahead of total emitted"):
            sink.since_mark(999)


class TestClear:
    async def test_clear_removes_all_keeps_counter(self):
        sink = CollectingAuditSink()
        for _ in range(5):
            await sink.emit(_make_event())
        sink.clear()
        assert sink.events == []
        assert sink.mark() == 5

    async def test_clear_invalidates_pre_clear_marks(self):
        sink = CollectingAuditSink()
        for _ in range(5):
            await sink.emit(_make_event())
        sink.mark()
        # Use mark at 3 (before clear) to test invalidation
        sink.clear()
        with pytest.raises(MarkEvictedError):
            sink.since_mark(3)

    async def test_clear_allows_post_clear_marks(self):
        sink = CollectingAuditSink()
        for _ in range(5):
            await sink.emit(_make_event())
        sink.clear()
        m = sink.mark()  # m = 5
        for _ in range(3):
            await sink.emit(_make_event())
        window = sink.since_mark(m)
        assert len(window) == 3


class TestOverflow:
    async def test_max_events_truncates_oldest(self):
        sink = CollectingAuditSink(max_events=3)
        for i in range(5):
            await sink.emit(_make_event(tool_name=f"tool_{i}"))
        events = sink.events
        assert len(events) == 3
        assert [e.tool_name for e in events] == ["tool_2", "tool_3", "tool_4"]

    async def test_max_events_configurable(self):
        sink_default = CollectingAuditSink()
        assert sink_default._max_events == 50_000

        sink_custom = CollectingAuditSink(max_events=100_000)
        assert sink_custom._max_events == 100_000

    def test_max_events_zero_rejected(self):
        with pytest.raises(ValueError, match="max_events must be >= 1"):
            CollectingAuditSink(max_events=0)

    def test_max_events_negative_rejected(self):
        with pytest.raises(ValueError, match="max_events must be >= 1"):
            CollectingAuditSink(max_events=-1)


class TestDefensiveCopy:
    async def test_events_returns_defensive_copy(self):
        sink = CollectingAuditSink()
        await sink.emit(_make_event())
        returned = sink.events
        returned.append(_make_event())
        assert len(sink.events) == 1


class TestSecurity:
    @pytest.mark.security
    async def test_collecting_sink_no_event_leak(self):
        sink = CollectingAuditSink()
        await sink.emit(_make_event())
        assert id(sink.events) != id(sink.events)

    @pytest.mark.security
    async def test_max_events_prevents_oom(self):
        sink = CollectingAuditSink(max_events=10)
        for _ in range(1000):
            await sink.emit(_make_event())
        assert len(sink.events) == 10

    @pytest.mark.security
    async def test_mark_evicted_not_silent(self):
        sink = CollectingAuditSink(max_events=5)
        for _ in range(20):
            await sink.emit(_make_event())
        # Buffer holds events 15-19. Evicted = 15.
        with pytest.raises(MarkEvictedError):
            sink.since_mark(0)
        with pytest.raises(MarkEvictedError):
            sink.since_mark(10)
        # Mark 15 is at buffer start — should work (returns events 15-19)
        result = sink.since_mark(15)
        assert len(result) == 5
