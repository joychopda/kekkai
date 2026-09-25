"""The rule-only backend: enforcement with no model, no download, and no vendor.

This is the promoted default. The Phase 3 benchmark is safety-gated, and no probabilistic
backend passed its gate, so none was promoted -- which is the outcome such a process is
supposed to produce when the candidates do not qualify, rather than shipping the least-bad one.

What it does and does not do is worth stating plainly, because the difference matters:

* Calls the deterministic layer recognises as dangerous are blocked, and calls it can
  positively prove safe are allowed. Both resolve in about two milliseconds.
* The **ambiguous middle is allowed**, with its category and the rule layer's own risk estimate
  recorded in the audit log.

That last point is the honest limitation. It is NOT the same as a fail-closed block, and the
distinction is deliberate: a configured backend that stops answering means something broke, so
KekkAI blocks; choosing rule-only enforcement means an operator decided which risks to take,
so KekkAI enforces what it knows and records the rest. A mode that blocked every unfamiliar
call would be switched off within a day, and a guardrail nobody runs protects nobody.
"""

from __future__ import annotations

import json

from ...application.errors import ClassifierUnavailable
from ...application.ports import ClassifierPort
from ...domain.categorise import categorise
from ...domain.model import Classification, Tier
from .registry import register_backend


@register_backend
class DeterministicClassifier(ClassifierPort):
    name = "deterministic"
    tier = Tier.COMMON

    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        try:
            document = json.loads(prompt)
        except json.JSONDecodeError as exc:  # pragma: no cover - our own format
            raise ClassifierUnavailable(f"malformed classifier prompt: {exc}") from exc
        return Classification(
            choice=categorise(document),
            # Abstention, not a confident acquittal. This backend expresses no opinion about
            # intent; anything it could have decided was already decided by a rule.
            malice_probability=0.0,
            vendor_confidence=None,
            backend=self.name,
        )
