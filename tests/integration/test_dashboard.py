"""The dashboard is a derived read path. It must never write, and never crash on a live log."""

from __future__ import annotations

import json

from kekkai.adapters.audit_sink import JsonlAuditSink
from kekkai.dashboard.server import read_events, summarize
from kekkai.domain.audit import AuditEvent, AuditRecord


def _record(event: AuditEvent, decision: str, score: int) -> AuditRecord:
    return AuditRecord(
        seq=0,
        ts=1000.0,
        segment_id="",
        session_id="s",
        event=event,
        tool_name="Bash",
        decision=decision,
        score=score,
        choice="privileged_system_call",
        malice_probability=0.9,
        backend_used="deterministic",
        execution_latency_ms=1.5,
        reason="r",
    )


def test_reads_events_and_summarizes(tmp_path):
    sink = JsonlAuditSink(tmp_path)
    sink.emit(_record(AuditEvent.BLOCKED, "block", 3))
    sink.emit(_record(AuditEvent.SCREENED, "allow", 0))
    sink.emit(_record(AuditEvent.FAILED_CLOSED, "block", 2))
    sink.aclose()

    events = read_events(tmp_path)
    summary = summarize(events, tmp_path)
    assert summary["screened"] == 3
    assert summary["blocked"] == 2
    assert summary["failed_closed"] == 1
    assert summary["chain"]["status"] == "ok"
    assert sum(summary["score_histogram"].values()) == 3


def test_reading_never_writes_to_the_log(tmp_path):
    sink = JsonlAuditSink(tmp_path)
    sink.emit(_record(AuditEvent.BLOCKED, "block", 3))
    sink.aclose()
    before = {p: p.read_bytes() for p in sorted(tmp_path.iterdir())}

    for _ in range(3):
        summarize(read_events(tmp_path), tmp_path)

    after = {p: p.read_bytes() for p in sorted(tmp_path.iterdir())}
    assert before == after, "the dashboard modified the audit log"


def test_a_truncated_tail_is_skipped_rather_than_crashing(tmp_path):
    """A segment being appended to right now is normal, not an error to surface."""
    sink = JsonlAuditSink(tmp_path)
    sink.emit(_record(AuditEvent.BLOCKED, "block", 3))
    sink.aclose()
    segment = next(tmp_path.glob("segment-*.jsonl"))
    with segment.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 1, "ts": 100')

    events = read_events(tmp_path)
    assert len(events) == 1
    assert summarize(events, tmp_path)["chain"]["status"] == "truncated_tail"


def test_an_empty_log_directory_summarizes_without_error(tmp_path):
    summary = summarize(read_events(tmp_path), tmp_path)
    assert summary["screened"] == 0
    assert summary["block_rate"] == 0.0


def test_events_are_newest_first_and_bounded(tmp_path):
    sink = JsonlAuditSink(tmp_path)
    for i in range(250):
        sink.emit(AuditRecord(**{**_record(AuditEvent.SCREENED, "allow", 0).__dict__, "ts": 1000.0 + i}))
    sink.aclose()
    events = read_events(tmp_path, limit=200)
    assert len(events) == 200
    assert events[0]["ts"] > events[-1]["ts"]


def test_the_served_page_requests_no_external_assets():
    """The dashboard must work offline and from a bare file server."""
    from pathlib import Path

    html = (Path(__file__).resolve().parents[2] / "kekkai" / "dashboard" / "index.html").read_text()
    assert "https://" not in html.replace("http://www.w3.org/2000/svg", "")
    assert 'rel="icon"' in html
    assert "<main>" in html


def test_api_payload_is_json_serializable(tmp_path):
    sink = JsonlAuditSink(tmp_path)
    sink.emit(_record(AuditEvent.BLOCKED, "block", 3))
    sink.aclose()
    events = read_events(tmp_path)
    json.dumps({"summary": summarize(events, tmp_path), "events": events})
