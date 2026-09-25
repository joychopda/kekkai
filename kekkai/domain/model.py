"""The screening vocabulary: what goes in, what comes out, and the invariants binding them.

These types are deliberately in one module rather than four. They change together — adding a
`Choice` member changes `Score` derivation and `GuardrailResult` validation — so splitting them
would be four interfaces for one cohesive concept (see docs/TECH-DEBT.md, smell #1).

Vendor vocabulary stops at the adapter boundary. Nothing here is called `state`, `confidence`,
or `score` in a backend's sense; see the glossary in docs/ARCHITECTURE.md for why that rename
is a security control rather than a style preference.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

# Approximate character budget for the classifier's 512-token context. Deliberately
# conservative: a truncated prompt is recorded on the result, never silently dropped.
PROMPT_CHAR_BUDGET = 2000


class TrustTag(StrEnum):
    """Where a piece of an envelope came from.

    The distinction that matters is TOOL_OUTPUT: content the agent fetched must never be
    allowed to authorize its own execution. TypeSafe documents that injected text can move a
    decision model's verdict, so tool output is fenced out of the classifier prompt entirely.
    """

    OPERATOR = "operator"
    MODEL = "model"
    TOOL_OUTPUT = "tool_output"


class Choice(StrEnum):
    """Exactly one category per tool call.

    The description on each member is the single source of the criteria text sent to every
    classifier backend — `kekkai.questions` generates the payload from this enum, so adding a
    member updates both backends and cannot drift (docs/TECH-DEBT.md, smell #4).
    """

    description: str

    SAFE_READ_ONLY = (
        "safe_read_only",
        "Reads data or inspects state without modifying anything and without sending data off the host.",
    )
    STATE_MODIFICATION = (
        "state_modification",
        "Creates, edits, moves, or deletes local files or local state within the working tree.",
    )
    PRIVILEGED_SYSTEM_CALL = (
        "privileged_system_call",
        "Executes a shell command, escalates privilege, changes system configuration, "
        "or reaches outside the working tree.",
    )
    EXTERNAL_EXFILTRATION = (
        "external_exfiltration",
        "Sends data to a network destination, especially credentials, keys, or files read from sensitive paths.",
    )

    def __new__(cls, value: str, description: str) -> Choice:
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.description = description
        return obj

    @classmethod
    def from_value(cls, value: str) -> Choice:
        """Look up a member by its wire value.

        Enum value-lookup works at runtime, but the two-argument `__new__` above makes a bare
        `Choice(value)` call look like a constructor to a type checker. Adapters translating a
        backend's answer use this instead.
        """
        for member in cls:
            if member.value == value:
                return member
        raise ValueError(f"unknown choice: {value!r}")


class Score(IntEnum):
    """Ordinal risk, 0 (safe) to 3 (critical).

    An IntEnum so it thresholds and compares directly. Note this is a 0-3 scale and the sibling
    repos use a 0-4 `Severity`; the two are deliberately not shared (docs/ARCHITECTURE.md).
    """

    SAFE = 0
    LOW = 1
    HIGH = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_name(cls, name: str) -> Score:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown score name: {name!r}") from exc


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class Tier(StrEnum):
    """Which latency budget a screening ran under."""

    COMMON = "common"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class RuleVerdict:
    """A deterministic rule's finding. Binding: a CRITICAL verdict cannot be downgraded.

    `source` and `rationale` are not decoration. A guardrail that denies a tool call must be
    able to say why, citing the corpus entry that justifies the rule -- borrowed from
    agent-action-sentinel's RULE_META convention.
    """

    rule: str
    score: Score
    message: str
    source: str
    rationale: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "score": int(self.score),
            "message": self.message,
            "source": self.source,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ToolCallEnvelope:
    """A proposed tool call in host-neutral form, with a trust tag per argument.

    The envelope owns the knowledge of its own trust boundaries: `classifier_prompt()` is a
    method here rather than a step in the interactor so the security-critical rule about which
    fields are trusted lives next to the data it governs (docs/TECH-DEBT.md, smell #6).
    """

    tool_name: str
    args: dict[str, object] = field(default_factory=dict)
    trust: dict[str, TrustTag] = field(default_factory=dict)
    resolved_paths: tuple[str, ...] = ()
    egress_hosts: tuple[str, ...] = ()
    argv: tuple[str, ...] = ()
    argv_parseable: bool = True
    session_id: str = ""

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("ToolCallEnvelope requires a tool_name")
        unknown = set(self.trust) - set(self.args)
        if unknown:
            raise ValueError(f"trust tags reference unknown args: {sorted(unknown)}")

    def trust_of(self, key: str) -> TrustTag:
        """Untagged arguments are assumed model-proposed -- the safe default."""
        return self.trust.get(key, TrustTag.MODEL)

    def fenced_fields(self) -> tuple[str, ...]:
        """Argument names withheld from the classifier because they carry untrusted content."""
        return tuple(sorted(k for k in self.args if self.trust_of(k) is TrustTag.TOOL_OUTPUT))

    def classifier_prompt(self) -> tuple[str, bool]:
        """Render the document handed to a classifier backend.

        Returns (prompt, truncated). Deliberately NOT called "state": the backends use that
        word for this input, and conflating it with `SessionState` is exactly how prior tool
        output reaches a classifier and moves its verdict.

        TOOL_OUTPUT-tagged arguments are excluded entirely. Their *names* are listed so the
        classifier knows content was withheld without ever seeing it, which is also what makes
        the omission auditable rather than invisible.
        """
        fenced = self.fenced_fields()
        visible = {k: v for k, v in self.args.items() if self.trust_of(k) is not TrustTag.TOOL_OUTPUT}
        document = {
            "tool_name": self.tool_name,
            "arguments": visible,
            "argv": list(self.argv),
            "argv_parseable": self.argv_parseable,
            "resolved_paths": list(self.resolved_paths),
            "egress_hosts": list(self.egress_hosts),
            "withheld_untrusted_fields": list(fenced),
        }
        rendered = json.dumps(document, sort_keys=True, default=str)
        if len(rendered) <= PROMPT_CHAR_BUDGET:
            return rendered, False
        return rendered[:PROMPT_CHAR_BUDGET], True

    def digest(self) -> str:
        """Stable identity of this proposed call, for cache keys and audit correlation."""
        payload = json.dumps(
            {
                "tool_name": self.tool_name,
                "args": self.args,
                "argv": list(self.argv),
                "resolved_paths": list(self.resolved_paths),
                "egress_hosts": list(self.egress_hosts),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GuardrailResult:
    """The immutable outcome of screening one tool call.

    Invariants, enforced here because callers act on this object to permit or deny execution:
      * a CRITICAL rule verdict forces BLOCK -- no probability downgrades it
      * a BLOCK carries a non-empty reason
      * malice_probability is in [0, 1]
      * backend_used and execution_latency_ms are populated even when failing closed

    This refines the brief's single `confidence` field into two. `malice_probability` is the
    calibrated P(true) that the 0.85 threshold reads; `vendor_confidence` is the backend's own
    self-reported certainty, which TypeSafe and the vLLM semantic-router evaluation both state
    is NOT a label probability. Thresholding the latter would be a calibration bug.
    """

    decision: Decision
    score: Score
    choice: Choice
    malice_probability: float
    backend_used: str
    execution_latency_ms: float
    reason: str = ""
    rule_verdicts: tuple[RuleVerdict, ...] = ()
    vendor_confidence: float | None = None
    tier: Tier = Tier.COMMON
    failed_closed: bool = False
    fenced_fields: tuple[str, ...] = ()
    prompt_truncated: bool = False
    cache_hit: bool = False
    session_id: str = ""
    envelope_digest: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.malice_probability <= 1.0:
            raise ValueError(f"malice_probability out of range: {self.malice_probability}")
        if self.execution_latency_ms < 0:
            raise ValueError("execution_latency_ms cannot be negative")
        if not self.backend_used:
            raise ValueError("backend_used must be populated, including on fail-closed results")
        if self.decision is Decision.BLOCK and not self.reason:
            raise ValueError("a BLOCK must cite a reason")
        critical = [v for v in self.rule_verdicts if v.score is Score.CRITICAL]
        if critical and self.decision is not Decision.BLOCK:
            raise ValueError(
                f"CRITICAL rule verdict {critical[0].rule!r} cannot be downgraded to {self.decision.value}"
            )

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "score": int(self.score),
            "score_label": self.score.label,
            "choice": self.choice.value,
            "malice_probability": round(self.malice_probability, 6),
            "vendor_confidence": self.vendor_confidence,
            "backend_used": self.backend_used,
            "execution_latency_ms": round(self.execution_latency_ms, 3),
            "reason": self.reason,
            "rule_verdicts": [v.to_dict() for v in self.rule_verdicts],
            "tier": self.tier.value,
            "failed_closed": self.failed_closed,
            "fenced_fields": list(self.fenced_fields),
            "prompt_truncated": self.prompt_truncated,
            "cache_hit": self.cache_hit,
            "session_id": self.session_id,
            "envelope_digest": self.envelope_digest,
        }


@dataclass(frozen=True)
class Classification:
    """A backend's risk assessment, already translated out of vendor vocabulary.

    This is a domain value object, not a port DTO, so `policy.decide()` can consume it without
    the domain ring importing anything from the application ring.
    """

    choice: Choice
    malice_probability: float
    rubric_score: float | None = None
    vendor_confidence: float | None = None
    backend: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.malice_probability <= 1.0:
            raise ValueError(f"malice_probability out of range: {self.malice_probability}")
