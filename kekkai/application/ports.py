"""The port interfaces the use case owns.

Defined here, in ring 2, and implemented outward in `kekkai.adapters` -- the dependency
inversion that keeps `langchain`, `laya`, and `typesafe` out of the decision engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..domain.audit import AuditRecord, ChainReport
from ..domain.model import Classification, GuardrailResult, Tier, ToolCallEnvelope
from ..domain.prefilter import SessionSnapshot


class ClassifierPort(ABC):
    """A risk classifier. Four implementations at v1: Laya, Jev, Replay, and a fake for tests.

    Implementations translate vendor vocabulary at this boundary: whatever a backend calls
    `state`, `score`, or `confidence`, what crosses inward is a `Classification`.
    """

    name: str = "unnamed"

    #: Which latency budget this backend may run under. Jev declares ESCALATED because its
    #: vendor p50-p95 (70-500 ms) cannot fit the 100 ms common-path deadline -- encoding
    #: "Jev is tier-2 only" in the type rather than in a comment (docs/RELIABILITY.md).
    tier: Tier = Tier.COMMON

    #: True when this backend returns a placeholder rather than a judgement. Nothing is
    #: learned by comparing a rule's verdict against an abstention, so shadow checks skip it.
    abstains: bool = False

    @abstractmethod
    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        """Assess a rendered classifier prompt.

        Must raise `ClassifierUnavailable` rather than returning a guess when it cannot answer
        within the deadline. Returning a low probability on failure would silently convert a
        fail-closed control into a fail-open one.
        """

    async def warmup(self) -> None:
        """Pay one-time initialization cost before the first real tool call.

        Optional: backends with nothing to warm inherit this no-op. Backends that lazily
        compile a graph must override it, or that cost lands on the first real tool call.
        """
        return None

    async def aclose(self) -> None:
        """Release connections or model memory. Optional."""
        return None


class AuditSinkPort(ABC):
    """The append-only, tamper-evident record."""

    @abstractmethod
    def emit(self, record: AuditRecord) -> AuditRecord:
        """Append one record, returning it with `seq` and `prev_hash` assigned."""

    @abstractmethod
    def flush(self) -> None: ...

    @abstractmethod
    def verify(self) -> ChainReport: ...

    def aclose(self) -> None:
        self.flush()


class ScreeningPort(ABC):
    """The inbound port: what a host adapter calls.

    Host adapters depend on this rather than on the concrete interactor, so a second host
    (Claude Code hooks, another framework) is a new adapter and not a refactor.
    """

    @abstractmethod
    async def screen(self, envelope: ToolCallEnvelope, session: SessionSnapshot) -> GuardrailResult: ...
