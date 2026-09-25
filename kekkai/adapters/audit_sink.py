"""Append-only JSONL audit sink with a per-process hash chain.

A hash chain is a read-modify-write, so several processes appending to one chain is textbook
write skew: both read tail `hash_k`, both append with `prev_hash = hash_k`, and the chain forks.
`O_APPEND` keeps the bytes un-interleaved but says nothing about read-modify-write atomicity.

So each process owns a segment with its own chain and takes no lock on the hot path. Segments
are named in a registry that is itself a hash chain, written once per segment rather than once
per tool call. Deleting a segment file leaves its registry entry dangling, and deleting the
registry entry breaks the registry's own chain -- so whole-file deletion stays detectable
without a lock anywhere near a 100 ms deadline.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import TextIO

from ..application.ports import AuditSinkPort
from ..domain.audit import GENESIS, AuditEvent, AuditRecord, ChainReport, ChainStatus, verify_lines

REGISTRY_NAME = "segments.jsonl"
DEFAULT_ROTATE_BYTES = 64 * 1024 * 1024


class JsonlAuditSink(AuditSinkPort):
    """One segment per process. Interval fsync, not per-record.

    fsync costs 1-10 ms against an 85-95 ms classifier budget, and the threat model here is
    tampering rather than power loss: a process crash loses nothing because the kernel holds
    the bytes. Power loss or a kernel panic costs at most `fsync_interval_s` of records, which
    is documented rather than hidden. Set `fsync_policy="always"` where that trade is wrong.
    """

    def __init__(
        self,
        log_dir: str | os.PathLike[str],
        *,
        fsync_policy: str = "interval",
        fsync_interval_s: float = 1.0,
        rotate_bytes: int = DEFAULT_ROTATE_BYTES,
    ):
        if fsync_policy not in ("never", "interval", "always"):
            raise ValueError("fsync_policy must be one of: never, interval, always")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.fsync_policy = fsync_policy
        self.fsync_interval_s = fsync_interval_s
        self.rotate_bytes = rotate_bytes

        self._seq = 0
        self._prev = GENESIS
        self._last_fsync = time.monotonic()
        self._segment_id = ""
        self._handle: TextIO | None = None
        self._open_segment()

    # -- segment lifecycle ---------------------------------------------------

    def _open_segment(self) -> None:
        previous = self._segment_id
        self._segment_id = f"{os.getpid()}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        self._seq = 0
        self._prev = GENESIS
        path = self.log_dir / f"segment-{self._segment_id}.jsonl"
        self._handle = path.open("a", encoding="utf-8")
        self._register(previous)

    def _register(self, previous_segment_id: str) -> None:
        """Append this segment to the registry, under an exclusive lock.

        Once per segment, not once per call -- the only place a lock touches this design.
        """
        import fcntl

        registry = self.log_dir / REGISTRY_NAME
        with registry.open("a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.seek(0)
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
                seq = len(lines)
                prev = GENESIS
                if lines:
                    try:
                        _rec, prev = AuditRecord.from_json(lines[-1])
                    except (ValueError, KeyError):
                        prev = GENESIS
                record = AuditRecord(
                    seq=seq,
                    ts=time.time(),
                    segment_id=self._segment_id,
                    session_id="",
                    event=AuditEvent.SEGMENT_OPENED,
                    prev_hash=prev,
                    extra={"pid": os.getpid(), "previous_segment_id": previous_segment_id},
                )
                fh.write(record.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _maybe_rotate(self) -> None:
        if self._handle and self._handle.tell() >= self.rotate_bytes:
            self.flush()
            self._handle.close()
            self._open_segment()

    # -- AuditSinkPort -------------------------------------------------------

    def emit(self, record: AuditRecord) -> AuditRecord:
        linked = AuditRecord(
            **{**record.__dict__, "seq": self._seq, "prev_hash": self._prev, "segment_id": self._segment_id}
        )
        assert self._handle is not None
        self._handle.write(linked.to_json() + "\n")
        self._prev = linked.compute_hash()
        self._seq += 1
        self._sync_if_due()
        self._maybe_rotate()
        return linked

    def _sync_if_due(self) -> None:
        if self.fsync_policy == "never" or self._handle is None:
            return
        now = time.monotonic()
        if self.fsync_policy == "always" or now - self._last_fsync >= self.fsync_interval_s:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._last_fsync = now

    def flush(self) -> None:
        if self._handle is None:
            return
        self._handle.flush()
        if self.fsync_policy != "never":
            os.fsync(self._handle.fileno())
        self._last_fsync = time.monotonic()

    def verify(self) -> ChainReport:
        self.flush()
        return verify_log_dir(self.log_dir)

    def aclose(self) -> None:
        self.flush()
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @property
    def segment_id(self) -> str:
        return self._segment_id

    @property
    def head(self) -> str:
        return self._prev


def verify_log_dir(log_dir: str | os.PathLike[str]) -> ChainReport:
    """Verify the registry, every segment it names, and that no named segment is missing.

    A truncated tail anywhere is reported as truncated, never as broken: a crash mid-write must
    not present as tampering, or the tamper signal stops being actionable.
    """
    directory = Path(log_dir)
    registry = directory / REGISTRY_NAME
    if not registry.exists():
        return ChainReport(status=ChainStatus.OK, checked=0, detail="no audit log present")

    registry_lines = registry.read_text(encoding="utf-8").splitlines()
    registry_report = verify_lines(registry_lines)
    if registry_report.status is ChainStatus.BROKEN:
        return ChainReport(
            status=ChainStatus.BROKEN,
            checked=registry_report.checked,
            head=registry_report.head,
            broken_at_seq=registry_report.broken_at_seq,
            detail=f"segment registry: {registry_report.detail}",
        )

    named: list[str] = []
    for line in registry_lines:
        if not line.strip():
            continue
        try:
            record, _ = AuditRecord.from_json(line)
        except (ValueError, KeyError):
            continue
        named.append(record.segment_id)

    total = registry_report.checked
    status = registry_report.status
    for segment_id in named:
        path = directory / f"segment-{segment_id}.jsonl"
        if not path.exists():
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=total,
                broken_at_seq=None,
                detail=f"segment {segment_id!r} is named in the registry but its file is missing",
            )
        report = verify_lines(path.read_text(encoding="utf-8").splitlines())
        if report.status is ChainStatus.BROKEN:
            return ChainReport(
                status=ChainStatus.BROKEN,
                checked=total + report.checked,
                head=report.head,
                broken_at_seq=report.broken_at_seq,
                detail=f"segment {segment_id}: {report.detail}",
            )
        if report.status is ChainStatus.TRUNCATED_TAIL:
            status = ChainStatus.TRUNCATED_TAIL
        total += report.checked

    return ChainReport(status=status, checked=total, detail=f"{len(named)} segment(s)")


class MemoryAuditSink(AuditSinkPort):
    """In-memory sink for tests. Keeps the same chain semantics as the real one."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self._prev = GENESIS

    def emit(self, record: AuditRecord) -> AuditRecord:
        linked = AuditRecord(
            **{**record.__dict__, "seq": len(self.records), "prev_hash": self._prev, "segment_id": "memory"}
        )
        self._prev = linked.compute_hash()
        self.records.append(linked)
        return linked

    def flush(self) -> None:
        return None

    def verify(self) -> ChainReport:
        return verify_lines([r.to_json() for r in self.records])
