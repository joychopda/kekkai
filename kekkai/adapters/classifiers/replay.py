"""Deterministic backends: recorded answers, and a fixed answer.

`ReplayClassifier` is what CI uses, so the test suite never calls a paid API and never needs a
1.7 GB model. An unknown digest raises rather than guessing -- a replay backend that invented a
low probability for unseen input would quietly turn every test green for the wrong reason.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...application.errors import ClassifierUnavailable
from ...application.ports import ClassifierPort
from ...domain.model import Choice, Classification
from .registry import register_backend


@register_backend
class ReplayClassifier(ClassifierPort):
    name = "replay"

    def __init__(self, recordings: dict[str, dict] | None = None):
        self._recordings = recordings or {}

    @classmethod
    def from_file(cls, path: str | Path) -> ReplayClassifier:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data.get("recordings", data))

    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        entry = self._recordings.get(prompt)
        if entry is None:
            raise ClassifierUnavailable("no recording for this prompt")
        return Classification(
            choice=Choice.from_value(entry["choice"]),
            malice_probability=float(entry["malice_probability"]),
            rubric_score=entry.get("rubric_score"),
            vendor_confidence=entry.get("vendor_confidence"),
            backend=entry.get("backend", self.name),
        )

    def record(self, prompt: str, classification: Classification) -> None:
        self._recordings[prompt] = {
            "choice": classification.choice.value,
            "malice_probability": classification.malice_probability,
            "rubric_score": classification.rubric_score,
            "vendor_confidence": classification.vendor_confidence,
            "backend": classification.backend,
        }


@register_backend
class StaticClassifier(ClassifierPort):
    """Always answers the same way. For tests that care about policy, not inference."""

    name = "static"

    def __init__(
        self,
        malice_probability: float = 0.0,
        choice: Choice = Choice.SAFE_READ_ONLY,
        *,
        vendor_confidence: float | None = None,
        delay_s: float = 0.0,
        fail: bool = False,
    ):
        self._probability = malice_probability
        self._choice = choice
        self._vendor_confidence = vendor_confidence
        self._delay_s = delay_s
        self._fail = fail
        self.calls = 0

    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        import asyncio

        self.calls += 1
        if self._delay_s:
            await asyncio.sleep(self._delay_s)
        if self._fail:
            raise ClassifierUnavailable("configured to fail")
        return Classification(
            choice=self._choice,
            malice_probability=self._probability,
            vendor_confidence=self._vendor_confidence,
            backend=self.name,
        )
