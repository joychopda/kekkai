"""Errors raised across the screening boundary."""

from __future__ import annotations

from ..domain.model import GuardrailResult


class KekkaiError(Exception):
    """Base for every error this package raises deliberately."""


class ToolBlockedError(KekkaiError):
    """A tool call was refused before execution.

    Hosts that prefer exceptions to error results raise this; the LangChain adapter returns a
    `ToolMessage(status="error")` instead so the agent runner halts gracefully rather than
    crashing the session.
    """

    def __init__(self, result: GuardrailResult):
        self.result = result
        super().__init__(result.reason or "tool call blocked by KekkAI")


class ClassifierUnavailable(KekkaiError):
    """A backend could not produce a usable answer.

    Never caught and swallowed into an allow: the interactor turns this into a fail-closed
    BLOCK plus a critical audit event.
    """
