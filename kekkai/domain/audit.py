"""The audit record and its hash chain -- the system of record.

This module owns the record format completely. The sink writes it, the dashboard reads it,
`kekkai verify` checks it, and the benchmarks aggregate it, but none of them indexes its keys
or calls `json.dumps` on one: that would be back-door format leakage, the subtlest kind
(docs/TECH-DEBT.md, smell #5).

Ported from agent-action-sentinel's SQLite chain. The hashing is unchanged; the storage is
append-only JSONL because a `BEGIN IMMEDIATE` per tool call is latency this system cannot
afford on the hot path.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum

SCHEMA_VERSION = 1
GENESIS = "0" * 64

# Field order is part of the hashing protocol. Appending is safe and requires a
# SCHEMA_VERSION bump; reordering or removing breaks every existing chain.
_HASH_FIELDS = (
    "schema_version",
    "seq",
    "ts",
    "segment_id",
    "session_id",
    "event",
    "tool_name",
    "decision",
    "score",
    "choice",
    "malice_probability",
    "backend_used",
    "execution_latency_ms",
    "reason",
    "envelope_digest",
    "prev_hash",
)


class AuditEvent(StrEnum):
    """Domain events, past tense. `SCREENED` is emitted for every decision."""

    SCREENED = "tool_call_screened"
    BLOCKED = "tool_call_blocked"
    FAILED_CLOSED = "classifier_failed_closed"
    PREFILTER_OVERRODE = "prefilter_overrode_classifier"
    SEGMENT_OPENED = "segment_opened"


class ChainStatus(StrEnum):
    """A crash is not an attack, and the two must never report the same way.

    `TRUNCATED_TAIL` is the expected result of a process dying mid-write. `BROKEN` means a
    record's content does not match its hash -- that is the tamper signal, and it stays
    actionable only because the crash case does not land here too.
    """

    OK = "ok"
    TRUNCATED_TAIL = "truncated_tail"
    BROKEN = "broken"


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: float
    segment_id: str
    session_id: str
    event: AuditEvent
    tool_name: str = ""
    decision: str = ""
    score: int = 0
    choice: str = ""
    malice_probability: float = 0.0
    backend_used: str = ""
    execution_latency_ms: float = 0.0
    reason: str = ""
    envelope_digest: str = ""
    prev_hash: str = GENESIS
    extra: dict = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def hashable(self) -> dict:
        raw = {
            "schema_version": self.schema_version,
            "seq": self.seq,
            "ts": self.ts,
            "segment_id": self.segment_id,
            "session_id": self.session_id,
            "event": self.event.value,
            "tool_name": self.tool_name,
            "decision": self.decision,
            "score": self.score,
            "choice": self.choice,
            "malice_probability": self.malice_probability,
            "backend_used": self.backend_used,
            "execution_latency_ms": self.execution_latency_ms,
            "reason": self.reason,
            "envelope_digest": self.envelope_digest,
            "prev_hash": self.prev_hash,
        }
        return {k: raw[k] for k in _HASH_FIELDS}

    def compute_hash(self) -> str:
        payload = json.dumps(self.hashable(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_json(self) -> str:
        body = self.hashable()
        body["extra"] = self.extra
        body["hash"] = self.compute_hash()
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> tuple[AuditRecord, str]:
        """Parse one line, returning the record and the hash it claims.

        Unknown fields are tolerated so a newer writer's log stays readable by an older reader
        -- the expand-contract constraint that makes rollback safe.
        """
        d = json.loads(line)
        record = cls(
            seq=d["seq"],
            ts=d["ts"],
            segment_id=d["segment_id"],
            session_id=d["session_id"],
            event=AuditEvent(d["event"]),
            tool_name=d.get("tool_name", ""),
            decision=d.get("decision", ""),
            score=d.get("score", 0),
            choice=d.get("choice", ""),
            malice_probability=d.get("malice_probability", 0.0),
            backend_used=d.get("backend_used", ""),
            execution_latency_ms=d.get("execution_latency_ms", 0.0),
            reason=d.get("reason", ""),
            envelope_digest=d.get("envelope_digest", ""),
            prev_hash=d.get("prev_hash", GENESIS),
            extra=d.get("extra", {}),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )
        return record, d.get("hash", "")


@dataclass(frozen=True)
class ChainReport:
    status: ChainStatus
    checked: int
    head: str = GENESIS
    broken_at_seq: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        """A truncated tail is survivable; a broken link is not."""
        return self.status is not ChainStatus.BROKEN

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "checked": self.checked,
            "head": self.head,
            "broken_at_seq": self.broken_at_seq,
            "detail": self.detail,
        }


def verify_lines(lines: Iterable[str], *, expected_genesis: str = GENESIS) -> ChainReport:
    """Verify one segment.

    Detects, in order: a record whose content does not match its stored hash, a broken
    prev_hash link, a non-monotonic sequence, and a malformed trailing line. Only the last of
    those is benign, and only when it really is the last line -- a malformed line in the middle
    is corruption, not a crash.
    """
    prev = expected_genesis
    checked = 0
    expected_seq = 0
    pending: str | None = None

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if pending is not None:
            # The previous line failed to parse but was not the last: corruption, not a crash.
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=checked,
                head=prev,
                broken_at_seq=expected_seq,
                detail="malformed record followed by further records",
            )
        try:
            record, claimed = AuditRecord.from_json(line)
        except (json.JSONDecodeError, KeyError, ValueError):
            pending = line
            continue

        if record.seq != expected_seq:
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=checked,
                head=prev,
                broken_at_seq=record.seq,
                detail=f"sequence gap: expected {expected_seq}, found {record.seq}",
            )
        if record.prev_hash != prev:
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=checked,
                head=prev,
                broken_at_seq=record.seq,
                detail="prev_hash does not match the preceding record",
            )
        actual = record.compute_hash()
        if actual != claimed:
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=checked,
                head=prev,
                broken_at_seq=record.seq,
                detail="record content does not match its stored hash",
            )
        prev = actual
        checked += 1
        expected_seq += 1

    if pending is not None:
        return ChainReport(
            status=ChainStatus.TRUNCATED_TAIL,
            checked=checked,
            head=prev,
            detail="final record is incomplete, consistent with a crash mid-write",
        )
    return ChainReport(status=ChainStatus.OK, checked=checked, head=prev)


def chain(records: Iterable[AuditRecord], *, start_hash: str = GENESIS) -> Iterator[AuditRecord]:
    """Re-link a sequence of records so each carries the previous one's hash."""
    prev = start_hash
    for i, rec in enumerate(records):
        linked = AuditRecord(**{**rec.__dict__, "seq": i, "prev_hash": prev})
        prev = linked.compute_hash()
        yield linked
