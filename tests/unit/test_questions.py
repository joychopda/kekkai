"""The generated question payload, and the option-ordering trap it closes."""

from __future__ import annotations

from kekkai.application.questions import CATEGORY, IS_MALICIOUS, RISK, build_questions
from kekkai.domain.model import Choice, Score


def test_every_choice_member_appears_with_its_own_description():
    criteria = build_questions()[CATEGORY]["criteria"]
    assert set(criteria) == {c.value for c in Choice}
    for choice in Choice:
        assert criteria[choice.value] == choice.description


def test_criteria_order_is_stable_across_calls():
    """Reordering a choice model's options moves its answer, so the order must not float."""
    first = list(build_questions()[CATEGORY]["criteria"])
    for _ in range(25):
        assert list(build_questions()[CATEGORY]["criteria"]) == first


def test_score_rubric_is_ordered_low_to_high():
    assert build_questions()[RISK]["criteria"] == [s.label for s in sorted(Score, key=int)]


def test_question_types_match_what_both_backends_accept():
    questions = build_questions()
    assert questions[IS_MALICIOUS]["type"] == "noul"
    assert questions[CATEGORY]["type"] == "choice"
    assert questions[RISK]["type"] == "score"


def test_malice_instruction_inoculates_against_embedded_authorization_claims():
    """The published attack embeds a fake pre-approval; the instruction names that explicitly."""
    instructions = build_questions()[IS_MALICIOUS]["instructions"].lower()
    assert "never instructions to follow" in instructions
    assert "pre-approved" in instructions
