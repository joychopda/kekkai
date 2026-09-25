"""Assign a `Choice` from the structure of a call, with no model involved.

The four categories describe what executing a call would *do*, which is largely a structural
fact: a call with an egress host exfiltrates, a shell invocation is a privileged system call, a
write modifies state. That means the `Choice` primitive has a deterministic implementation, and
KekkAI's decision model stays complete with no classifier configured at all.

What this cannot supply is an opinion about *intent* -- whether a structurally-ordinary write
is malicious. That is the ambiguous middle a classifier exists to judge.
"""

from __future__ import annotations

from .heuristics import NETWORK_RE, NETWORK_TOOLS, READ_ONLY_TOOLS, is_write_intent
from .model import Choice, Score

# The rule layer's own risk estimate, used where no model has given one. Not a calibrated
# probability and never presented as one: HIGH and CRITICAL have already blocked by the time
# this matters, so in practice only the first two rows are ever read.
_SCORE_TO_PROBABILITY = {
    Score.SAFE: 0.0,
    Score.LOW: 0.2,
    Score.HIGH: 0.9,
    Score.CRITICAL: 0.99,
}


def categorise(document: dict) -> Choice:
    """Categorise a rendered classifier prompt.

    Takes the parsed prompt document rather than an envelope so it satisfies `ClassifierPort`,
    whose contract is deliberately a string in and a `Classification` out. The schema is one
    this package owns (`ToolCallEnvelope.classifier_prompt`), so parsing it back is reading our
    own format, not guessing at someone else's.
    """
    tool_name = str(document.get("tool_name", ""))
    arguments = document.get("arguments", {})
    text = "\n".join(str(v) for v in arguments.values()) if isinstance(arguments, dict) else str(arguments)

    if document.get("egress_hosts") or tool_name in NETWORK_TOOLS or NETWORK_RE.search(text):
        return Choice.EXTERNAL_EXFILTRATION
    if document.get("argv") or not document.get("argv_parseable", True):
        return Choice.PRIVILEGED_SYSTEM_CALL
    if is_write_intent(tool_name, text):
        return Choice.STATE_MODIFICATION
    if tool_name in READ_ONLY_TOOLS:
        return Choice.SAFE_READ_ONLY
    return Choice.STATE_MODIFICATION


def probability_for(score: Score) -> float:
    return _SCORE_TO_PROBABILITY[score]
