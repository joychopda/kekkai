"""Serve the telemetry dashboard from the standard library.

The dashboard is a derived read path over the audit log -- the log is the changelog, the page
is the materialized view -- so it can be deleted and rebuilt at any time, and it never holds
the log exclusively or writes to it.

Binds to loopback by default. This surface exposes blocked commands and the paths an agent
touched, which is exactly what an attacker would like to read.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from ..adapters.audit_sink import REGISTRY_NAME, verify_log_dir
from ..domain.audit import AuditRecord

STATIC = Path(__file__).resolve().parent
MAX_RECORDS = 200


def read_events(log_dir: Path, limit: int = MAX_RECORDS) -> list[dict]:
    """Read the tail of every segment, newest first.

    Reads only up to the last complete line: a segment being appended to right now is normal,
    and a partial final line is a crash artifact rather than an error to surface here.
    """
    events: list[dict] = []
    for path in sorted(log_dir.glob("segment-*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                record, _ = AuditRecord.from_json(line)
            except (ValueError, KeyError):
                continue  # truncated tail
            events.append(
                {
                    "ts": record.ts,
                    "segment": record.segment_id,
                    "session": record.session_id,
                    "event": record.event.value,
                    "tool": record.tool_name,
                    "decision": record.decision,
                    "score": record.score,
                    "choice": record.choice,
                    "probability": record.malice_probability,
                    "backend": record.backend_used,
                    "latency_ms": record.execution_latency_ms,
                    "reason": record.reason,
                    "rules": [v.get("rule") for v in record.extra.get("rule_verdicts", [])],
                    "fenced": record.extra.get("fenced_fields", []),
                }
            )
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:limit]


def summarize(events: list[dict], log_dir: Path) -> dict:
    screened = [e for e in events if e["event"] != "segment_opened"]
    blocked = [e for e in screened if e["decision"] == "block"]
    failed = [e for e in screened if e["event"] == "classifier_failed_closed"]
    overrides = [e for e in screened if e["event"] == "prefilter_overrode_classifier"]
    latencies = sorted(e["latency_ms"] for e in screened) or [0.0]
    chain = verify_log_dir(log_dir)
    return {
        "screened": len(screened),
        "blocked": len(blocked),
        "block_rate": round(len(blocked) / len(screened), 4) if screened else 0.0,
        "failed_closed": len(failed),
        "prefilter_overrides": len(overrides),
        "p50_ms": round(latencies[len(latencies) // 2], 2),
        "p95_ms": round(latencies[min(int(len(latencies) * 0.95), len(latencies) - 1)], 2),
        "score_histogram": {str(s): sum(1 for e in screened if e["score"] == s) for s in range(4)},
        "backends": sorted({e["backend"] for e in screened if e["backend"]}),
        "chain": chain.to_dict(),
    }


def make_handler(log_dir: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "kekkai"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()
            if not getattr(self, "_head_only", False):
                self.wfile.write(body)

        def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
            """Answer HEAD properly rather than 501.

            Link checkers and uptime probes lead with HEAD, and a 501 there reads as an outage.
            """
            self._head_only = True
            try:
                self.do_GET()
            finally:
                self._head_only = False

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif path == "/app.js":
                self._send(200, (STATIC / "app.js").read_bytes(), "application/javascript; charset=utf-8")
            elif path == "/styles.css":
                self._send(200, (STATIC / "styles.css").read_bytes(), "text/css; charset=utf-8")
            elif path == "/api/state":
                events = read_events(log_dir)
                payload = {
                    "summary": summarize(events, log_dir),
                    "events": [e for e in events if e["event"] != "segment_opened"][:100],
                    "log_dir": str(log_dir),
                    "registry": (log_dir / REGISTRY_NAME).exists(),
                }
                self._send(200, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def log_message(self, fmt: str, *args: object) -> None:
            return  # the audit log is the record; request spam is not

    return Handler


def serve(log_dir: Path, *, host: str = "127.0.0.1", port: int = 8787) -> None:
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((host, port), make_handler(log_dir))
    print(f"kekkai dashboard on http://{host}:{port}  (reading {log_dir})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
