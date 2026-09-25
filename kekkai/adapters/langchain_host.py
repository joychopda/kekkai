"""LangChain host adapter.

The interception boundary is `AgentMiddleware.wrap_tool_call` (LangChain 1.x), which runs
after the model proposes a tool call and before the tool function executes. Returning a
`ToolMessage` with `status="error"` short-circuits: the handler is never invoked, so the tool
never runs, and the agent runner halts gracefully instead of crashing the session.

This module is the only place in KekkAI that imports `langchain`.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ..application.errors import ToolBlockedError
from ..application.ports import ScreeningPort
from ..domain.model import GuardrailResult, Score
from ..domain.prefilter import SessionSnapshot
from .envelope_builder import build_envelope

# Declared as Any so the two assignment branches below are both well-typed. Without this the
# suppressions needed here would flip depending on whether the `langchain` extra happens to be
# installed in the checking environment, which makes the type gate unreliable rather than
# strict.
ToolMessage: Any
LANGCHAIN_AVAILABLE: bool

try:
    from langchain.messages import ToolMessage as _ToolMessage

    ToolMessage = _ToolMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the no-langchain import test
    ToolMessage = None
    LANGCHAIN_AVAILABLE = False

# Subclass LangChain's middleware when it is installed and a plain object when it is not, so
# this module imports either way. Type checking always sees the plain base.
if TYPE_CHECKING:
    _MiddlewareBase = object
else:  # pragma: no cover - branch depends on the installed extra
    try:
        from langchain.agents.middleware import AgentMiddleware as _MiddlewareBase
    except ImportError:
        _MiddlewareBase = object


def block_message(result: GuardrailResult) -> str:
    """Operator-readable refusal, citing what decided it.

    The agent sees this text, so it states the reason plainly rather than a generic denial: an
    agent told only "blocked" will retry the same call, while one told which rule fired can
    choose a different approach.
    """
    head = f"KekkAI blocked this tool call [{result.score.label.lower()}/{result.choice.value}]: {result.reason}"
    if result.rule_verdicts:
        cites = "; ".join(f"{v.rule} ({v.source})" for v in result.rule_verdicts)
        return f"{head}\nDeterministic rules: {cites}"
    return head


class GuardrailMiddleware(_MiddlewareBase):
    """Screens every tool call before it executes.

    Carries the outermost fail-closed backstop: any unexpected exception -- including a bug in
    KekkAI itself -- becomes a block, never a pass-through. "Crash early" is right for a
    program; a guardrail that crashes into an open gate is the worst possible outcome.
    """

    def __init__(
        self,
        screener: ScreeningPort,
        *,
        session_id: str = "",
        raise_on_block: bool = False,
    ):
        if LANGCHAIN_AVAILABLE:
            super().__init__()
        self.screener = screener
        self.session_id = session_id
        self.raise_on_block = raise_on_block
        self._session = SessionSnapshot(session_id=session_id)

    # -- the interception point ---------------------------------------------

    async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
        result = await self._screen(request)
        if result.blocked:
            return self._refuse(request, result)
        return await handler(request)

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        """Synchronous hosts. Runs the async core on a private loop.

        Never reuses a running loop: if one is already running in this thread, the async
        variant should have been used, and silently nesting would deadlock.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            result = asyncio.run(self._screen(request))
        else:  # pragma: no cover - misuse path
            raise RuntimeError("an event loop is already running; use awrap_tool_call")
        if result.blocked:
            return self._refuse(request, result)
        return handler(request)

    # -- internals -----------------------------------------------------------

    async def _screen(self, request: Any) -> GuardrailResult:
        """Build an envelope from the proposed call and screen it.

        Only `request.tool_call` is read. `request.state` is deliberately ignored: that is
        LangChain's agent state, which carries prior tool outputs, and feeding it to a
        classifier is exactly the path by which fetched content authorizes its own execution.
        LangChain shipped middleware filtering tool outputs from classifier inputs for this
        reason; here the filtering is structural, because the untrusted field is never read.
        """
        try:
            tool_call = getattr(request, "tool_call", request)
            name = tool_call.get("name", "") if isinstance(tool_call, dict) else getattr(tool_call, "name", "")
            args = tool_call.get("args", {}) if isinstance(tool_call, dict) else getattr(tool_call, "args", {})
            envelope = build_envelope(name or "unknown", args or {}, session_id=self.session_id)
            return await self.screener.screen(envelope, self._session)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            return self._backstop(exc)

    def _backstop(self, exc: Exception) -> GuardrailResult:
        from ..domain.model import Choice, Decision

        return GuardrailResult(
            decision=Decision.BLOCK,
            score=Score.CRITICAL,
            choice=Choice.PRIVILEGED_SYSTEM_CALL,
            malice_probability=1.0,
            backend_used="backstop",
            execution_latency_ms=0.0,
            reason=f"guardrail raised {type(exc).__name__}; failing closed rather than permitting the call",
            failed_closed=True,
        )

    def _refuse(self, request: Any, result: GuardrailResult) -> Any:
        if self.raise_on_block:
            raise ToolBlockedError(result)
        tool_call = getattr(request, "tool_call", request)
        call_id = tool_call.get("id", "") if isinstance(tool_call, dict) else getattr(tool_call, "id", "")
        if ToolMessage is None:  # pragma: no cover - no langchain installed
            raise ToolBlockedError(result)
        return ToolMessage(content=block_message(result), tool_call_id=call_id or "kekkai", status="error")
