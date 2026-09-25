"""The tracer bullet: one thin, fully real slice through every ring.

LangChain middleware -> envelope + trust tagging -> deterministic rule -> policy -> real
JSONL audit sink on disk -> chain verification, with the tool's side effect proven not to have
happened. No model download, no API key, milliseconds to run.

This is the first CI gate. If it fails, the wiring is broken and no other result means anything.
"""

from __future__ import annotations

import json

from langchain.messages import ToolMessage
from langchain.tools.tool_node import ToolCallRequest

from kekkai.adapters.audit_sink import JsonlAuditSink, verify_log_dir
from kekkai.adapters.classifiers.replay import StaticClassifier
from kekkai.adapters.langchain_host import GuardrailMiddleware
from kekkai.application.screen_tool_call import ScreenToolCall
from kekkai.domain.audit import AuditEvent, ChainStatus
from kekkai.domain.model import Score


async def test_tracer_bullet_blocks_a_destructive_call_through_every_ring(tmp_path):
    executed: list[str] = []

    async def dangerous_tool(request):
        # If this line ever runs, the guardrail has failed at its only job.
        executed.append(request.tool_call["args"]["command"])
        return ToolMessage(content="deleted", tool_call_id="call-1")

    sink = JsonlAuditSink(tmp_path)
    screener = ScreenToolCall(StaticClassifier(malice_probability=0.0), sink, workspace_root="/proj")
    middleware = GuardrailMiddleware(screener, session_id="tracer")

    request = ToolCallRequest(
        tool_call={"name": "Bash", "args": {"command": "rm -rf ~/.ssh"}, "id": "call-1", "type": "tool_call"},
        tool=None,
        state={"messages": []},
        runtime=None,
    )

    response = await middleware.awrap_tool_call(request, dangerous_tool)
    sink.aclose()

    # 1. the tool never ran
    assert executed == [], "the destructive command executed despite being blocked"

    # 2. the agent gets a graceful error, not a crash
    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert "mass_delete" in response.content

    # 3. a real record landed on disk
    segments = list(tmp_path.glob("segment-*.jsonl"))
    assert len(segments) == 1
    lines = [json.loads(line) for line in segments[0].read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    record = lines[0]
    assert record["event"] == AuditEvent.BLOCKED.value
    assert record["decision"] == "block"
    assert record["score"] == int(Score.CRITICAL)
    assert record["tool_name"] == "Bash"
    assert record["reason"]

    # 4. the chain verifies
    report = verify_log_dir(tmp_path)
    assert report.status is ChainStatus.OK, report.detail


async def test_tracer_bullet_lets_a_safe_call_through(tmp_path):
    """The same slice in the allow direction. A gate that only proves blocking proves half."""
    executed: list[str] = []

    async def safe_tool(request):
        executed.append(request.tool_call["args"]["file_path"])
        return ToolMessage(content="contents", tool_call_id="call-2")

    sink = JsonlAuditSink(tmp_path)
    screener = ScreenToolCall(StaticClassifier(malice_probability=0.0), sink, workspace_root="/proj")
    middleware = GuardrailMiddleware(screener, session_id="tracer")

    request = ToolCallRequest(
        tool_call={"name": "Read", "args": {"file_path": "src/main.py"}, "id": "call-2", "type": "tool_call"},
        tool=None,
        state={"messages": []},
        runtime=None,
    )
    response = await middleware.awrap_tool_call(request, safe_tool)
    sink.aclose()

    assert executed == ["src/main.py"]
    assert response.status != "error"
    assert verify_log_dir(tmp_path).status is ChainStatus.OK
