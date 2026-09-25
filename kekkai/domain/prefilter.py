"""The deterministic layer: rules a probability cannot argue with.

This is the part of KekkAI that injected text cannot move. TypeSafe documents that a
decision model's verdict shifts under adversarial input, and their own guidance is that guards
built on it work "alongside deterministic checks, not instead of them". These are those checks.

The registry follows supply-chain-hunter's proven shape, deliberately close to
`importlib.metadata` entry points so it could be swapped later without touching a call site.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .heuristics import READ_ONLY_TOOLS
from .model import RuleVerdict, Score, ToolCallEnvelope

_RULES: dict[str, type[Rule]] = {}


def register_rule(cls: type[Rule]) -> type[Rule]:
    name = getattr(cls, "name", None)
    if not name:
        raise ValueError(f"{cls.__name__} must define a class-level `name`")
    _RULES[name] = cls
    return cls


def all_rules() -> dict[str, type[Rule]]:
    return dict(_RULES)


@dataclass(frozen=True)
class SessionSnapshot:
    """An immutable view of session history, handed to rules.

    Immutable on purpose: a rule that could mutate session state could influence its own future
    verdicts, which is a self-referential loop an attacker would enjoy. Only the interactor
    mutates, once, after the decision is made.
    """

    session_id: str = ""
    last_secret_access_ts: float = 0.0
    last_secret_desc: str = ""
    flagged_entities: frozenset[str] = frozenset()
    seen_hosts: frozenset[str] = frozenset()
    now: float = 0.0


@dataclass(frozen=True)
class RuleContext:
    envelope: ToolCallEnvelope
    session: SessionSnapshot = field(default_factory=SessionSnapshot)
    workspace_root: str = ""
    egress_allowlist: frozenset[str] = frozenset()
    secrets_network_window_s: float = 120.0

    def text(self) -> str:
        """Every string in the envelope's visible arguments, flattened for scanning."""
        parts = [self.envelope.tool_name]
        for value in self.envelope.args.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, (list, tuple)):
                parts.extend(str(v) for v in value)
            else:
                parts.append(str(value))
        return "\n".join(parts)


class Rule(ABC):
    """One deterministic check.

    `source` and `rationale` are required, not optional colour: a guardrail that denies a tool
    call has to be able to say why, citing what justifies the rule.
    """

    name: str = ""
    source: str = ""
    rationale: str = ""

    @abstractmethod
    def evaluate(self, ctx: RuleContext) -> RuleVerdict | None: ...

    def verdict(self, score: Score, message: str) -> RuleVerdict:
        return RuleVerdict(
            rule=self.name, score=score, message=message, source=self.source, rationale=self.rationale
        )


@dataclass(frozen=True)
class PrefilterResult:
    verdicts: tuple[RuleVerdict, ...]
    trivially_safe: bool


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self._rules = rules

    @classmethod
    def default(cls) -> RuleEngine:
        from . import rules as _rules_pkg  # noqa: F401  -- triggers registration

        return cls([rule_cls() for rule_cls in all_rules().values()])

    def evaluate(self, ctx: RuleContext) -> PrefilterResult:
        verdicts = tuple(v for v in (r.evaluate(ctx) for r in self._rules) if v is not None)
        return PrefilterResult(verdicts=verdicts, trivially_safe=self._trivially_safe(ctx, verdicts))

    @staticmethod
    def _trivially_safe(ctx: RuleContext, verdicts: tuple[RuleVerdict, ...]) -> bool:
        """A *positive* determination that a call needs no classifier at all.

        Absence of findings is not safety. This asks the stronger question -- is the tool
        incapable of modifying state or reaching the network, with nothing sensitive in its
        arguments -- because this is the predicate that keeps agents working when a classifier
        is unavailable, and a loose answer here would quietly widen the whole system's
        attack surface.
        """
        env = ctx.envelope
        if verdicts:
            return False
        if env.tool_name not in READ_ONLY_TOOLS:
            return False
        if not env.argv_parseable:
            return False
        if env.egress_hosts:
            return False
        from .heuristics import SECRET_RE

        return not SECRET_RE.search(ctx.text())
