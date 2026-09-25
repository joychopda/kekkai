"""The screening policy: the one place a threshold or deadline is written down.

Every other module -- adapters, benchmarks, the dashboard, tests -- receives a
`ScreeningPolicy` rather than naming a number. The literal 0.85 appears exactly once in this
codebase, immediately below (docs/TECH-DEBT.md, smell #3).

This is a domain rule, not deployment configuration, which is why it lives here and not in
`config`: the domain ring must not import outward.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Choice, Classification, Decision, RuleVerdict, Score, Tier

# Base risk implied by the category alone, before any probability is considered.
_CHOICE_BASE_SCORE: dict[Choice, Score] = {
    Choice.SAFE_READ_ONLY: Score.SAFE,
    Choice.STATE_MODIFICATION: Score.LOW,
    Choice.PRIVILEGED_SYSTEM_CALL: Score.HIGH,
    Choice.EXTERNAL_EXFILTRATION: Score.HIGH,
}


@dataclass(frozen=True)
class ScreeningPolicy:
    """Thresholds and deadlines. Immutable; construct a new one to change behaviour.

    There is deliberately no flag that disables the deterministic prefilter. Rule severity is
    tunable; the layer itself is not switchable. A guardrail with a setting that silently turns
    off its uninjectable layer is a footgun (docs/TECH-DEBT.md, Adopted Conventions).
    """

    block_threshold: float = 0.85
    elevated_threshold: float = 0.50
    common_deadline_ms: float = 100.0
    escalated_deadline_ms: float = 500.0
    classifier_deadline_ms: float = 95.0
    escalate_at_or_above: Score = Score.HIGH
    binding_rule_score: Score = Score.HIGH

    #: After a deterministic rule blocks, ask the classifier anyway -- off the hot path,
    #: with the decision already fixed -- purely to record when it disagrees. That
    #: disagreement is the production symptom of a classifier being argued out of a correct
    #: verdict, and it is unobservable without asking. Inference is paid only on blocks,
    #: which are rare, and never before a decision is returned.
    shadow_classify_blocks: bool = True

    #: One budget covering a cold model load as well as the inference. Generous on purpose:
    #: the shadow runs after the decision is already returned, so spending time here costs the
    #: agent nothing, and in a one-shot process the shadow is often the first thing to need
    #: the model at all. A tight budget here does not protect anyone -- it just silently
    #: loses the signal, which is how this was found.
    shadow_budget_ms: float = 30_000.0

    def __post_init__(self) -> None:
        if not 0.0 < self.block_threshold <= 1.0:
            raise ValueError("block_threshold must be in (0, 1]")
        if self.elevated_threshold >= self.block_threshold:
            raise ValueError("elevated_threshold must sit below block_threshold")
        if self.classifier_deadline_ms >= self.common_deadline_ms:
            raise ValueError(
                "classifier_deadline_ms must leave room inside common_deadline_ms for "
                "envelope construction, policy evaluation, and the audit append"
            )

    @classmethod
    def default(cls) -> ScreeningPolicy:
        return cls()

    def deadline_for(self, tier: Tier) -> float:
        return self.common_deadline_ms if tier is Tier.COMMON else self.escalated_deadline_ms

    def should_escalate(self, score: Score) -> bool:
        return score >= self.escalate_at_or_above


@dataclass(frozen=True)
class PolicyOutcome:
    decision: Decision
    score: Score
    choice: Choice
    reason: str
    failed_closed: bool = False


def max_rule_score(verdicts: tuple[RuleVerdict, ...]) -> Score:
    return max((v.score for v in verdicts), default=Score.SAFE)


def derive_score(choice: Choice, malice_probability: float, policy: ScreeningPolicy) -> Score:
    """Ordinal risk from the category and the calibrated probability.

    The probability escalates the category's base risk rather than replacing it: a call that is
    structurally an exfiltration stays HIGH even when the model is unsure, because the category
    is a fact about the call and the probability is an opinion about intent.
    """
    base = _CHOICE_BASE_SCORE[choice]
    if malice_probability >= policy.block_threshold:
        return Score.CRITICAL
    if malice_probability >= policy.elevated_threshold:
        return Score(min(int(base) + 1, int(Score.CRITICAL)))
    return base


def decide(
    verdicts: tuple[RuleVerdict, ...],
    classification: Classification | None,
    *,
    trivially_safe: bool,
    policy: ScreeningPolicy,
) -> PolicyOutcome:
    """Resolve one screening.

    Precedence, in order:
      1. A deterministic verdict at or above `binding_rule_score` blocks. Binding -- no
         probability downgrades it, which is what makes the layer uninjectable.
      2. With no classification (timeout, error, breaker open, absent credential), a
         positively-determined trivially-safe call is still allowed; everything else fails
         closed. Only the ambiguous middle is blocked when a backend is down.
      3. Otherwise the calibrated probability decides against `block_threshold`.

    `classification is None` means "no usable answer", never "assume benign".
    """
    rule_score = max_rule_score(verdicts)

    if rule_score >= policy.binding_rule_score:
        worst = max(verdicts, key=lambda v: int(v.score))
        return PolicyOutcome(
            decision=Decision.BLOCK,
            score=rule_score,
            choice=classification.choice if classification else Choice.PRIVILEGED_SYSTEM_CALL,
            reason=f"deterministic rule {worst.rule!r}: {worst.message}",
        )

    if classification is None:
        if trivially_safe and rule_score is Score.SAFE:
            return PolicyOutcome(
                decision=Decision.ALLOW,
                score=Score.SAFE,
                choice=Choice.SAFE_READ_ONLY,
                reason="",
                failed_closed=False,
            )
        return PolicyOutcome(
            decision=Decision.BLOCK,
            score=max(rule_score, Score.HIGH),
            choice=Choice.PRIVILEGED_SYSTEM_CALL,
            reason="classifier unavailable and call is not positively safe; failing closed",
            failed_closed=True,
        )

    score = max(derive_score(classification.choice, classification.malice_probability, policy), rule_score)
    if classification.malice_probability >= policy.block_threshold:
        return PolicyOutcome(
            decision=Decision.BLOCK,
            score=score,
            choice=classification.choice,
            reason=(
                f"malice probability {classification.malice_probability:.3f} "
                f">= threshold {policy.block_threshold:.2f} ({classification.choice.value})"
            ),
        )
    return PolicyOutcome(decision=Decision.ALLOW, score=score, choice=classification.choice, reason="")
