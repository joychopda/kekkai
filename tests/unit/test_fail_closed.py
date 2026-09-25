"""Fail-closed: every way a backend can let us down resolves to BLOCK.

Each of these would be a silent security hole if it resolved the other way, so they are tested
one failure mode at a time rather than as a single "errors are handled" assertion.
"""

from __future__ import annotations

import asyncio

import pytest

from kekkai.adapters.audit_sink import MemoryAuditSink
from kekkai.adapters.classifiers.replay import ReplayClassifier, StaticClassifier
from kekkai.adapters.envelope_builder import build_envelope
from kekkai.application.errors import ClassifierUnavailable
from kekkai.application.ports import ClassifierPort
from kekkai.application.screen_tool_call import ScreenToolCall
from kekkai.domain.audit import AuditEvent
from kekkai.domain.model import Choice, Classification, Decision, Score
from kekkai.domain.policy import ScreeningPolicy
from kekkai.domain.prefilter import SessionSnapshot

AMBIGUOUS = ("Bash", {"command": "python deploy.py --env prod"})


def screener(classifier: ClassifierPort, **kwargs) -> tuple[ScreenToolCall, MemoryAuditSink]:
    sink = MemoryAuditSink()
    return ScreenToolCall(classifier, sink, workspace_root="/proj", **kwargs), sink


async def screen(classifier: ClassifierPort, tool=AMBIGUOUS, **kwargs):
    use_case, sink = screener(classifier, **kwargs)
    envelope = build_envelope(tool[0], tool[1], session_id="s1")
    return await use_case.screen(envelope, SessionSnapshot(session_id="s1")), sink


async def test_a_raising_backend_fails_closed():
    result, _ = await screen(StaticClassifier(fail=True))
    assert result.decision is Decision.BLOCK
    assert result.failed_closed


async def test_a_backend_that_exceeds_the_deadline_fails_closed():
    """The deadline is a real timeout, not advice: a slow backend must not stall a tool call."""
    policy = ScreeningPolicy(classifier_deadline_ms=20.0)
    result, _ = await screen(StaticClassifier(delay_s=0.5), policy=policy)
    assert result.decision is Decision.BLOCK
    assert result.failed_closed


async def test_an_unparseable_backend_response_fails_closed():
    class Garbage(ClassifierPort):
        name = "garbage"

        async def classify(self, prompt: str, *, deadline_ms: float):
            raise ClassifierUnavailable("unparseable response")

    result, _ = await screen(Garbage())
    assert result.failed_closed


async def test_an_unexpected_backend_exception_fails_closed():
    """Not just our own error type -- any exception at all."""

    class Exploding(ClassifierPort):
        name = "exploding"

        async def classify(self, prompt: str, *, deadline_ms: float):
            raise RuntimeError("something nobody anticipated")

    result, _ = await screen(Exploding())
    assert result.decision is Decision.BLOCK
    assert result.failed_closed


async def test_a_replay_miss_fails_closed_rather_than_guessing():
    result, _ = await screen(ReplayClassifier({}))
    assert result.failed_closed


async def test_fail_closed_emits_a_critical_audit_event():
    _result, sink = await screen(StaticClassifier(fail=True))
    assert sink.records[-1].event is AuditEvent.FAILED_CLOSED


async def test_fail_closed_results_still_carry_backend_and_latency():
    """Required by the result's own invariant, and the reason an outage is measurable."""
    result, _ = await screen(StaticClassifier(fail=True))
    assert result.backend_used
    assert result.execution_latency_ms >= 0


async def test_a_backend_outage_still_allows_positively_safe_calls():
    """The degradation path: a classifier outage must not block an agent's every read."""
    result, _ = await screen(StaticClassifier(fail=True), tool=("Read", {"command": "src/main.py"}))
    assert result.decision is Decision.ALLOW
    assert not result.failed_closed


async def test_a_binding_rule_blocks_without_ever_calling_the_backend():
    """Short-circuit: the latency fix and the cost control, verified by call count."""
    classifier = StaticClassifier(malice_probability=0.0)
    result, _ = await screen(classifier, tool=("Bash", {"command": "rm -rf ~/.ssh"}))
    assert result.decision is Decision.BLOCK
    assert result.score is Score.CRITICAL
    assert classifier.calls == 0


async def test_a_positively_safe_call_never_calls_the_backend_either():
    classifier = StaticClassifier(malice_probability=0.99)
    result, _ = await screen(classifier, tool=("Read", {"command": "src/main.py"}))
    assert result.decision is Decision.ALLOW
    assert classifier.calls == 0


async def test_vendor_confidence_is_carried_but_never_thresholded():
    """Jev's confidence is not a label probability; thresholding it would be a calibration bug."""
    classifier = StaticClassifier(
        malice_probability=0.10, choice=Choice.STATE_MODIFICATION, vendor_confidence=0.99
    )
    result, _ = await screen(classifier)
    assert result.vendor_confidence == 0.99
    assert result.decision is Decision.ALLOW, "high vendor confidence in a LOW risk must not block"


async def test_repeated_identical_calls_hit_the_cache_instead_of_the_backend():
    classifier = StaticClassifier(malice_probability=0.1, choice=Choice.STATE_MODIFICATION)
    use_case, _sink = screener(classifier)
    envelope = build_envelope(*AMBIGUOUS, session_id="s1")
    session = SessionSnapshot(session_id="s1")
    first = await use_case.screen(envelope, session)
    second = await use_case.screen(envelope, session)
    assert classifier.calls == 1
    assert not first.cache_hit and second.cache_hit


async def test_the_cache_key_changes_once_a_secret_has_been_read():
    """A verdict that was right before the agent touched a credential may not be right after."""
    classifier = StaticClassifier(malice_probability=0.1, choice=Choice.STATE_MODIFICATION)
    use_case, _sink = screener(classifier)
    envelope = build_envelope(*AMBIGUOUS, session_id="s1")
    await use_case.screen(envelope, SessionSnapshot(session_id="s1"))
    await use_case.screen(envelope, SessionSnapshot(session_id="s1", last_secret_access_ts=100.0))
    assert classifier.calls == 2


async def test_concurrent_screenings_do_not_interleave_into_a_broken_chain():
    classifier = StaticClassifier(malice_probability=0.1, choice=Choice.STATE_MODIFICATION)
    use_case, sink = screener(classifier)
    envelopes = [build_envelope("Bash", {"command": f"echo {i}"}, session_id="s1") for i in range(20)]
    await asyncio.gather(*(use_case.screen(e, SessionSnapshot(session_id="s1")) for e in envelopes))
    assert sink.verify().ok
    assert len(sink.records) == 20


@pytest.mark.parametrize("probability", [0.0, 0.5, 0.84, 0.85, 0.99])
async def test_the_threshold_holds_end_to_end_through_the_interactor(probability):
    classifier = StaticClassifier(malice_probability=probability, choice=Choice.STATE_MODIFICATION)
    result, _ = await screen(classifier)
    assert result.blocked is (probability >= 0.85)


async def test_a_fail_closed_block_is_not_cached_past_the_outage():
    """Caching an outage would turn a transient failure into a persistent one."""
    flaky = StaticClassifier(fail=True)
    use_case, _sink = screener(flaky)
    envelope = build_envelope(*AMBIGUOUS, session_id="s1")
    session = SessionSnapshot(session_id="s1")
    first = await use_case.screen(envelope, session)
    assert first.failed_closed

    use_case.classifier = StaticClassifier(malice_probability=0.05, choice=Choice.STATE_MODIFICATION)
    recovered = await use_case.screen(envelope, session)
    assert recovered.decision is Decision.ALLOW
    assert not recovered.cache_hit


async def test_a_deterministic_block_is_not_served_from_cache():
    classifier = StaticClassifier(malice_probability=0.0)
    use_case, _sink = screener(classifier)
    envelope = build_envelope("Bash", {"command": "rm -rf ~/.ssh"}, session_id="s1")
    session = SessionSnapshot(session_id="s1")
    for _ in range(3):
        result = await use_case.screen(envelope, session)
        assert result.blocked and not result.cache_hit


def test_classification_rejects_an_out_of_range_probability():
    with pytest.raises(ValueError, match="malice_probability"):
        Classification(choice=Choice.SAFE_READ_ONLY, malice_probability=-0.1)


async def test_a_short_circuited_allow_does_not_report_certainty_of_malice():
    """`ALLOW ... p(malicious)=1.000` is a contradiction a reader has to talk themselves out of.

    A positively-safe call resolved without a classifier is a determination of safety, not an
    unknown, so the published probability has to say so.
    """
    result, _ = await screen(StaticClassifier(fail=True), tool=("Read", {"command": "src/main.py"}))
    assert result.decision is Decision.ALLOW
    assert result.malice_probability == 0.0


async def test_a_fail_closed_block_still_reports_full_malice_probability():
    result, _ = await screen(StaticClassifier(fail=True))
    assert result.decision is Decision.BLOCK
    assert result.malice_probability == 1.0


async def test_the_prefilter_override_signal_is_currently_unreachable():
    """Pins a known gap rather than a desired behaviour.

    `PrefilterOverrodeClassifier` is documented as the production symptom of a classifier
    being injected: the deterministic layer blocking something a model rated safe. But a
    binding rule short-circuits *before* the classifier is consulted, so `classification` is
    always None on exactly the path where the override would be computed, and the flag can
    never be True.

    The short-circuit is deliberate and worth keeping -- it is the latency and cost decision.
    Making the signal real means classifying blocked calls out of band, after the decision is
    fixed, which is a design change and not a bug fix. This test fails the day that lands,
    which is the point: it is the reminder, and it stops the claim being quietly forgotten.
    """
    classifier = StaticClassifier(malice_probability=0.01, choice=Choice.SAFE_READ_ONLY)
    result, _ = await screen(classifier, tool=("Bash", {"command": "rm -rf ~/.ssh"}))

    assert result.decision is Decision.BLOCK
    assert classifier.calls == 0, "a binding rule must not pay for inference"
    assert not result.prefilter_overrode_classifier, (
        "if this now fires, the override signal became reachable -- update the docs that "
        "describe it and delete this test"
    )
