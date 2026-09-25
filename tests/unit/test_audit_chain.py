"""Chain integrity, and the distinction between a crash and an attack."""

from __future__ import annotations

import json

from kekkai.adapters.audit_sink import JsonlAuditSink, verify_log_dir
from kekkai.domain.audit import AuditEvent, AuditRecord, ChainStatus, chain, verify_lines


def _records(n: int = 5) -> list[AuditRecord]:
    return [
        AuditRecord(
            seq=0,
            ts=1000.0 + i,
            segment_id="seg",
            session_id="s1",
            event=AuditEvent.BLOCKED,
            tool_name="Bash",
            decision="block",
            score=3,
            reason="r",
        )
        for i in range(n)
    ]


def _lines(n: int = 5) -> list[str]:
    return [r.to_json() for r in chain(_records(n))]


def test_a_clean_chain_verifies():
    report = verify_lines(_lines())
    assert report.status is ChainStatus.OK
    assert report.checked == 5


def test_in_place_tampering_is_caught_at_the_edited_record():
    lines = _lines()
    edited = json.loads(lines[2])
    edited["reason"] = "totally harmless"
    lines[2] = json.dumps(edited, sort_keys=True, separators=(",", ":"))
    report = verify_lines(lines)
    assert report.status is ChainStatus.BROKEN
    assert report.broken_at_seq == 2


def test_deleting_a_record_is_caught_at_the_gap():
    lines = _lines()
    report = verify_lines(lines[:2] + lines[3:])
    assert report.status is ChainStatus.BROKEN
    assert report.broken_at_seq == 3


def test_a_torn_final_line_reports_as_truncation_not_tampering():
    """A crash mid-write must not present as an attack, or the tamper signal becomes noise."""
    lines = _lines()
    report = verify_lines(lines[:4] + ['{"seq": 4, "ts": 100'])
    assert report.status is ChainStatus.TRUNCATED_TAIL
    assert report.broken_at_seq is None
    assert report.ok, "a truncated tail is survivable"


def test_a_malformed_line_in_the_middle_is_corruption_not_a_crash():
    lines = _lines()
    report = verify_lines(lines[:2] + ['{"seq": 2, "ts": 100'] + lines[3:])
    assert report.status is ChainStatus.BROKEN


def test_unknown_fields_are_tolerated_so_an_older_reader_can_read_a_newer_log():
    """Expand-contract: this is the constraint that makes a version rollback safe."""
    lines = _lines(2)
    body = json.loads(lines[0])
    body["a_field_from_the_future"] = {"nested": True}
    record, claimed = AuditRecord.from_json(json.dumps(body))
    assert record.seq == 0
    assert claimed == body["hash"], "an added field outside the hashed set must not change the hash"


def test_sink_writes_a_verifiable_segment(tmp_path):
    sink = JsonlAuditSink(tmp_path)
    for record in _records(3):
        sink.emit(record)
    sink.aclose()
    report = verify_log_dir(tmp_path)
    assert report.status is ChainStatus.OK
    assert report.checked == 4, "three screenings plus the segment-opened registry record"


def test_deleting_a_whole_segment_file_is_detected_through_the_registry(tmp_path):
    """The reason per-process segments still give tamper-evidence without a shared lock."""
    sink = JsonlAuditSink(tmp_path)
    sink.emit(_records(1)[0])
    sink.aclose()
    for path in tmp_path.glob("segment-*.jsonl"):
        path.unlink()
    report = verify_log_dir(tmp_path)
    assert report.status is ChainStatus.BROKEN
    assert "missing" in report.detail


def test_two_sinks_in_one_directory_do_not_fork_a_chain(tmp_path):
    """Concurrent appends to one chain would be write skew; separate segments avoid it."""
    first, second = JsonlAuditSink(tmp_path), JsonlAuditSink(tmp_path)
    for _ in range(3):
        first.emit(_records(1)[0])
        second.emit(_records(1)[0])
    first.aclose()
    second.aclose()
    assert first.segment_id != second.segment_id
    assert verify_log_dir(tmp_path).status is ChainStatus.OK


def test_fsync_policy_is_validated(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="fsync_policy"):
        JsonlAuditSink(tmp_path, fsync_policy="sometimes")
