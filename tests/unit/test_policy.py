"""Policy: the 0.85 boundary, score derivation, and precedence."""

from __future__ import annotations

import pytest

from kekkai.domain.model import Choice, Classification, Decision, RuleVerdict, Score
from kekkai.domain.policy import ScreeningPolicy, decide, derive_score

POLICY = ScreeningPolicy.default()


def _classification(probability: float, choice: Choice = Choice.STATE_MODIFICATION) -> Classification:
    return Classification(choice=choice, malice_probability=probability, backend="test")


@pytest.mark.parametrize(
    "probability,expected",
    [
        (0.0, Decision.ALLOW),
        (0.5, Decision.ALLOW),
        (0.8499, Decision.ALLOW),
        (0.85, Decision.BLOCK),
        (1.0, Decision.BLOCK),
    ],
)
def test_threshold_boundary_is_inclusive_at_exactly_085(probability, expected):
    """0.85 itself blocks. The spec says >= 0.85, and an off-by-one here is a security bug."""
    assert decide((), _classification(probability), trivially_safe=False, policy=POLICY).decision is expected


def test_probability_just_below_threshold_still_allows():
    outcome = decide((), _classification(0.8499999), trivially_safe=False, policy=POLICY)
    assert outcome.decision is Decision.ALLOW


def test_critical_rule_cannot_be_downgraded_by_a_confident_safe_verdict():
    """The whole point of the deterministic layer: no probability argues it down."""
    verdicts = (RuleVerdict("mass_delete", Score.CRITICAL, "rm -rf ~", "src", "why"),)
    outcome = decide(verdicts, _classification(0.001, Choice.SAFE_READ_ONLY), trivially_safe=True, policy=POLICY)
    assert outcome.decision is Decision.BLOCK
    assert outcome.score is Score.CRITICAL
    assert outcome.prefilter_overrode_classifier, "an override must be flagged; it is the injection signal"


def test_low_rule_verdict_alone_does_not_block():
    verdicts = (RuleVerdict("shell_exec", Score.LOW, "invokes a shell", "src", "why"),)
    assert decide(verdicts, _classification(0.1), trivially_safe=False, policy=POLICY).decision is Decision.ALLOW


def test_missing_classification_blocks_the_ambiguous_middle():
    outcome = decide((), None, trivially_safe=False, policy=POLICY)
    assert outcome.decision is Decision.BLOCK
    assert outcome.failed_closed


def test_missing_classification_still_allows_a_positively_safe_call():
    """Degradation path: a classifier outage must not block everything, or agents stop working."""
    outcome = decide((), None, trivially_safe=True, policy=POLICY)
    assert outcome.decision is Decision.ALLOW
    assert not outcome.failed_closed


@pytest.mark.parametrize(
    "choice,probability,expected",
    [
        (Choice.SAFE_READ_ONLY, 0.0, Score.SAFE),
        (Choice.SAFE_READ_ONLY, 0.6, Score.LOW),
        (Choice.STATE_MODIFICATION, 0.0, Score.LOW),
        (Choice.PRIVILEGED_SYSTEM_CALL, 0.0, Score.HIGH),
        (Choice.EXTERNAL_EXFILTRATION, 0.6, Score.CRITICAL),
        (Choice.SAFE_READ_ONLY, 0.9, Score.CRITICAL),
    ],
)
def test_score_derives_from_category_and_probability(choice, probability, expected):
    assert derive_score(choice, probability, POLICY) is expected


def test_score_never_falls_below_the_rule_verdict():
    verdicts = (RuleVerdict("path_escape", Score.HIGH, "outside tree", "src", "why"),)
    outcome = decide(verdicts, _classification(0.01, Choice.SAFE_READ_ONLY), trivially_safe=False, policy=POLICY)
    assert outcome.score >= Score.HIGH


def test_policy_rejects_a_classifier_deadline_that_leaves_no_room():
    with pytest.raises(ValueError, match="classifier_deadline_ms"):
        ScreeningPolicy(common_deadline_ms=100.0, classifier_deadline_ms=100.0)


def test_policy_rejects_an_elevated_threshold_above_the_block_threshold():
    with pytest.raises(ValueError, match="elevated_threshold"):
        ScreeningPolicy(block_threshold=0.5, elevated_threshold=0.9)
