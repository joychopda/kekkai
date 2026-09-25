"""Jev backend -- TypeSafe's hosted System One decision API.

`POST https://api.typesafe.ai/v1/systemone`, bearer auth, 70-500 ms typical.

Declared `Tier.ESCALATED` because that latency cannot fit the 100 ms common-path deadline.
That is encoded in the type rather than left as advice: "Jev is tier-2 only" then holds by
construction instead of by remembering (docs/RELIABILITY.md).

Two translation rules matter here. Jev's `confidence` is NOT a label probability -- TypeSafe
says so, and the vLLM semantic-router evaluation restates it -- so it crosses inward as
`vendor_confidence`, for telemetry, and is never thresholded. The thresholded value is the
`noul` probability alone.
"""

from __future__ import annotations

import os
from typing import Any

from ...application.errors import ClassifierUnavailable
from ...application.ports import ClassifierPort
from ...application.questions import CATEGORY, IS_MALICIOUS, RISK, build_questions
from ...domain.model import Choice, Classification, Tier
from .registry import register_backend

DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"


@register_backend
class JevClassifier(ClassifierPort):
    name = "jev"
    tier = Tier.ESCALATED

    def __init__(
        self,
        api_key: str | None = None,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        connect_timeout_s: float = 0.15,
    ):
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY", "")
        self.endpoint = endpoint
        self.model = model
        self.connect_timeout_s = connect_timeout_s
        self._questions = build_questions()
        self._client: Any = None

    def _ensure_client(self, deadline_ms: float) -> Any:
        if not self.api_key:
            raise ClassifierUnavailable("TYPESAFE_API_KEY is not set")
        if self._client is None:
            try:
                import httpx
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise ClassifierUnavailable("the `jev` extra is not installed") from exc
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    deadline_ms / 1000.0, connect=self.connect_timeout_s, read=deadline_ms / 1000.0
                ),
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        return self._client

    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        client = self._ensure_client(deadline_ms)
        payload = {"model": self.model, "state": prompt, "questions": self._questions}
        try:
            response = await client.post(self.endpoint, json=payload)
        except Exception as exc:  # noqa: BLE001 - every transport failure is a failure to answer
            raise ClassifierUnavailable(f"Jev transport error: {type(exc).__name__}") from exc

        if response.status_code != 200:
            # 401/422/429/529 all mean the same thing to a fail-closed control: no usable
            # answer. There is no retry -- a retry cannot complete inside the deadline, and
            # the circuit breaker is what absorbs a sustained pattern.
            raise ClassifierUnavailable(f"Jev returned HTTP {response.status_code}")
        return self._translate(response.json())

    def _translate(self, body: dict) -> Classification:
        """Anti-corruption layer: Jev's answer shape becomes a domain `Classification`."""
        try:
            answers = body.get("answers", body)
            malice = answers[IS_MALICIOUS]
            probability = float(malice["noul"])
            category = answers[CATEGORY]
            choice = Choice.from_value(category["choice"])
            rubric = answers.get(RISK, {}).get("score")
            confidence = category.get("confidence", malice.get("confidence"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ClassifierUnavailable(f"unparseable Jev response: {exc}") from exc
        return Classification(
            choice=choice,
            malice_probability=probability,
            rubric_score=float(rubric) if rubric is not None else None,
            vendor_confidence=float(confidence) if confidence is not None else None,
            backend=self.name,
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
