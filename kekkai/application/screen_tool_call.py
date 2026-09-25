"""The single use case: screen one proposed tool call and decide whether it may run."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from ..domain.audit import AuditEvent, AuditRecord
from ..domain.model import (
    Classification,
    Decision,
    GuardrailResult,
    Score,
    Tier,
    ToolCallEnvelope,
)
from ..domain.policy import ScreeningPolicy, decide
from ..domain.prefilter import RuleContext, RuleEngine, SessionSnapshot
from .cache import DecisionCache, cache_key
from .errors import ClassifierUnavailable
from .ports import AuditSinkPort, ClassifierPort, ScreeningPort


def _probability_of(classification: Classification | None, outcome) -> float:
    """The probability to publish on a result.

    With a classification, its own number -- including when a deterministic rule overrode it,
    because the gap between a low probability and a BLOCK is exactly the override signal.

    Without one, the decision has to speak for itself: a short-circuited allow is a positive
    determination of safety, not an unknown, and reporting 1.0 beside ALLOW is a contradiction
    a reader has to talk themselves out of. Fail-closed blocks keep 1.0.
    """
    if classification is not None:
        return classification.malice_probability
    return 0.0 if outcome.decision is Decision.ALLOW else 1.0


class ScreenToolCall(ScreeningPort):
    """Orchestrates prefilter, classifier, policy, and audit for one tool call.

    The ordering is a latency decision as much as a security one: a binding rule verdict and a
    positively-safe call both resolve in about 2 ms without touching a classifier, so inference
    is spent only on the ambiguous middle.
    """

    def __init__(
        self,
        classifier: ClassifierPort,
        sink: AuditSinkPort,
        *,
        policy: ScreeningPolicy | None = None,
        engine: RuleEngine | None = None,
        cache: DecisionCache | None = None,
        workspace_root: str = "",
        egress_allowlist: frozenset[str] = frozenset(),
        clock: Callable[[], float] = time.perf_counter,
    ):
        self.classifier = classifier
        self.sink = sink
        self.policy = policy or ScreeningPolicy.default()
        self.engine = engine or RuleEngine.default()
        self.cache = cache if cache is not None else DecisionCache()
        self.workspace_root = workspace_root
        self.egress_allowlist = egress_allowlist
        self._clock = clock
        self._shadow_tasks: set[asyncio.Task] = set()

    async def warmup(self) -> None:
        """Pre-warm the backend so lazy initialization is not charged to the first tool call."""
        await self.classifier.warmup()

    async def screen(self, envelope: ToolCallEnvelope, session: SessionSnapshot) -> GuardrailResult:
        started = self._clock()
        ctx = RuleContext(
            envelope=envelope,
            session=session,
            workspace_root=self.workspace_root,
            egress_allowlist=self.egress_allowlist,
        )
        prefilter = self.engine.evaluate(ctx)
        binding = max((v.score for v in prefilter.verdicts), default=Score.SAFE) >= self.policy.binding_rule_score

        key = cache_key(envelope.digest(), session)
        classification: Classification | None = None
        cached = None

        if binding or prefilter.trivially_safe:
            # Short-circuit: the deterministic layer already has the answer.
            pass
        else:
            cached = self.cache.get(key)
            if cached is None:
                classification = await self._classify(envelope)

        if cached is not None:
            result = self._rehydrate(cached, envelope, session, self._elapsed_ms(started))
        else:
            outcome = decide(
                prefilter.verdicts,
                classification,
                trivially_safe=prefilter.trivially_safe,
                policy=self.policy,
            )
            prompt_truncated = classification is not None and envelope.classifier_prompt()[1]
            result = GuardrailResult(
                decision=outcome.decision,
                score=outcome.score,
                choice=outcome.choice,
                malice_probability=_probability_of(classification, outcome),
                backend_used=self.classifier.name,
                execution_latency_ms=self._elapsed_ms(started),
                reason=outcome.reason,
                rule_verdicts=prefilter.verdicts,
                vendor_confidence=classification.vendor_confidence if classification else None,
                tier=self.classifier.tier,
                failed_closed=outcome.failed_closed,
                fenced_fields=envelope.fenced_fields(),
                prompt_truncated=prompt_truncated,
                session_id=session.session_id,
                envelope_digest=envelope.digest(),
            )
            self.cache.put(key, result)

        self._audit(result, envelope, session)
        if binding and result.blocked:
            self._schedule_shadow(envelope, session, result)
        return result

    # -- shadow checks -------------------------------------------------------

    def _schedule_shadow(self, envelope: ToolCallEnvelope, session: SessionSnapshot, result) -> None:
        """Queue an out-of-band classification of a call a rule already blocked.

        Deliberately fire-and-forget: the decision has been made and returned, so this must
        never delay it. Without a running loop there is nothing to schedule and the signal is
        simply unavailable -- which is better than blocking a synchronous caller to get it.
        """
        if not self.policy.shadow_classify_blocks or self.classifier.abstains:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self._shadow_check(envelope, session, result))
        self._shadow_tasks.add(task)
        task.add_done_callback(self._shadow_tasks.discard)

    async def _shadow_check(self, envelope: ToolCallEnvelope, session: SessionSnapshot, result) -> None:
        """Record the case where the classifier would not have blocked what a rule did.

        Agreement is not logged. A guardrail that emitted an event every time its two layers
        concurred would bury the one case worth alerting on, and it is the disagreement that
        signals a classifier being talked out of a correct verdict.
        """
        prompt, _truncated = envelope.classifier_prompt()
        try:
            classification = await asyncio.wait_for(
                self._shadow_classify(prompt),
                timeout=self.policy.shadow_budget_ms / 1000.0,
            )
        except Exception:
            # A shadow that cannot answer changes nothing: the block already stands, and the
            # absence of a disagreement record is not evidence of agreement.
            return
        if classification.malice_probability >= self.policy.block_threshold:
            return

        worst = max(result.rule_verdicts, key=lambda v: int(v.score)) if result.rule_verdicts else None
        self.sink.emit(
            AuditRecord(
                seq=0,
                ts=time.time(),
                segment_id="",
                session_id=session.session_id,
                event=AuditEvent.PREFILTER_OVERRODE,
                tool_name=envelope.tool_name,
                decision=result.decision.value,
                score=int(result.score),
                choice=classification.choice.value,
                malice_probability=classification.malice_probability,
                backend_used=self.classifier.name,
                execution_latency_ms=0.0,
                reason=(
                    f"rule {worst.rule!r} blocked; {self.classifier.name} rated it "
                    f"{classification.malice_probability:.3f}, below the "
                    f"{self.policy.block_threshold:.2f} threshold"
                    if worst
                    else "deterministic block the classifier would not have made"
                ),
                envelope_digest=envelope.digest(),
                extra={"shadow": True, "rule_verdicts": [v.to_dict() for v in result.rule_verdicts]},
            )
        )

    async def _shadow_classify(self, prompt: str) -> Classification:
        """Load the model if needed, then classify. Both inside the shadow's own budget."""
        await self.classifier.warmup()
        return await self.classifier.classify(prompt, deadline_ms=self.policy.shadow_budget_ms)

    async def drain_shadows(self, timeout: float | None = None) -> None:
        """Await any in-flight shadow checks.

        Needed by short-lived callers -- the CLI, tests -- that would otherwise exit before
        the signal they asked for has been written.
        """
        pending = set(self._shadow_tasks)
        if pending:
            await asyncio.wait(pending, timeout=timeout)

    async def _classify(self, envelope: ToolCallEnvelope) -> Classification | None:
        """Call the backend under a hard deadline.

        Returns None on any failure. None means "no usable answer", never "assume benign" --
        `decide()` turns it into a fail-closed block for anything not positively safe.
        """
        prompt, _truncated = envelope.classifier_prompt()
        deadline_ms = (
            self.policy.classifier_deadline_ms
            if self.classifier.tier is Tier.COMMON
            else self.policy.escalated_deadline_ms
        )
        try:
            return await asyncio.wait_for(
                self.classifier.classify(prompt, deadline_ms=deadline_ms),
                timeout=deadline_ms / 1000.0,
            )
        except (TimeoutError, ClassifierUnavailable):
            return None
        except Exception:
            # Any unexpected backend failure is still a failure to answer. A guardrail that
            # let an unknown exception through would be an open gate.
            return None

    def _rehydrate(
        self,
        cached: GuardrailResult,
        envelope: ToolCallEnvelope,
        session: SessionSnapshot,
        latency_ms: float,
    ) -> GuardrailResult:
        return GuardrailResult(
            **{
                **cached.__dict__,
                "execution_latency_ms": latency_ms,
                "cache_hit": True,
                "session_id": session.session_id,
                "envelope_digest": envelope.digest(),
            }
        )

    def _audit(self, result: GuardrailResult, envelope: ToolCallEnvelope, session: SessionSnapshot) -> None:
        """Emit exactly one record per screening, labelled with its most specific event.

        One line per call keeps the hot path cheap; labelling by the most specific event keeps
        the interesting ones greppable without a second write.
        """
        if result.failed_closed:
            event = AuditEvent.FAILED_CLOSED
        elif result.decision is Decision.BLOCK:
            event = AuditEvent.BLOCKED
        else:
            event = AuditEvent.SCREENED

        self.sink.emit(
            AuditRecord(
                seq=0,
                ts=time.time(),
                segment_id="",
                session_id=session.session_id,
                event=event,
                tool_name=envelope.tool_name,
                decision=result.decision.value,
                score=int(result.score),
                choice=result.choice.value,
                malice_probability=result.malice_probability,
                backend_used=result.backend_used,
                execution_latency_ms=result.execution_latency_ms,
                reason=result.reason,
                envelope_digest=result.envelope_digest,
                extra={
                    "rule_verdicts": [v.to_dict() for v in result.rule_verdicts],
                    "fenced_fields": list(result.fenced_fields),
                    "tier": result.tier.value,
                    "cache_hit": result.cache_hit,
                    "prompt_truncated": result.prompt_truncated,
                },
            )
        )

    def _elapsed_ms(self, started: float) -> float:
        return max((self._clock() - started) * 1000.0, 0.0)
