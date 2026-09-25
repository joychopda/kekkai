"""Laya backend -- air-gapped local inference.

Laya is an open-weights System-1 decision model (Apache 2.0, ModernBERT-large, 421M params)
that answers typed questions in a single forward pass with calibrated probabilities. After the
one-time model download it makes no network calls, which is what makes it viable in an
air-gapped deployment.

Vendor vocabulary stops here. What Laya calls `state` is a `ClassifierPrompt` on the way in,
and its `score` becomes `rubric_score` on the way out -- see the glossary in
docs/ARCHITECTURE.md for why that rename is a security control and not a style choice.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ...application.errors import ClassifierUnavailable
from ...application.ports import ClassifierPort
from ...application.questions import CATEGORY, IS_MALICIOUS, RISK, build_questions
from ...domain.model import Choice, Classification, Tier
from .registry import register_backend

DEFAULT_CHECKPOINT = "convaiinnovations/laya"


@register_backend
class LayaClassifier(ClassifierPort):
    """Local inference behind a bounded thread pool.

    A PyTorch forward pass cannot be cancelled: when `asyncio.wait_for` times out, control
    returns to us but the thread keeps computing. An unbounded pool would therefore accumulate
    threads under slow inference -- the blocked-threads anti-pattern arriving through a local
    dependency. Hence a dedicated two-worker pool with no queue: when both workers are busy,
    the next call fails closed in about two milliseconds instead of piling up.
    """

    name = "laya"
    tier = Tier.COMMON

    def __init__(
        self,
        checkpoint: str = DEFAULT_CHECKPOINT,
        *,
        max_workers: int | None = None,
        subfolder: str | None = None,
        device: str | None = None,
        fast: bool = False,
    ):
        self.checkpoint = checkpoint
        self.subfolder = subfolder
        #: Inference device. None lets Laya choose; "mps", "cpu", or "cuda" force one. The
        #: vendor's ~33 ms figure is a T4 GPU number and the card lists 193-464 ms on CPU, so
        #: on Apple Silicon this choice decides whether the common-path deadline is reachable
        #: at all. The benchmark sweeps it rather than assuming.
        self.device = device
        self.fast = fast
        if max_workers is None:
            # Metal rejects concurrent command encoding from multiple threads -- a two-worker
            # pool crashes the process with "a command encoder is already encoding to this
            # command buffer". So the bulkhead is one worker wide on MPS. It still bounds the
            # pool, which is what the bulkhead is for; only its width is device-dependent.
            max_workers = 1 if (device or "").lower() == "mps" else 2
        self._agent: Any = None
        self._questions = build_questions()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="kekkai-laya")
        self._inflight = 0
        self._max_workers = max_workers
        # Serializes access to the model itself. The executor bounds how many calls are in
        # flight; this guarantees only one is inside the framework at a time, which Metal
        # requires and which costs nothing when the pool is already one worker wide.
        self._predict_lock = threading.Lock()

    async def warmup(self) -> None:
        """Load the model and run one throwaway inference.

        A first call carries lazy graph compilation. Paying it here keeps a multi-second
        penalty off the first real tool call.
        """
        await asyncio.get_running_loop().run_in_executor(self._executor, self._load)
        try:
            await self.classify('{"tool_name": "warmup"}', deadline_ms=60_000)
        except ClassifierUnavailable:
            pass

    def _load(self) -> Any:
        if self._agent is None:
            try:
                import laya
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise ClassifierUnavailable("the `laya` extra is not installed") from exc
            kwargs: dict = {"fast": self.fast}
            if self.subfolder:
                kwargs["subfolder"] = self.subfolder
            if self.device:
                kwargs["device"] = self.device
            self._agent = laya.load(self.checkpoint, **kwargs)
        return self._agent

    async def classify(self, prompt: str, *, deadline_ms: float) -> Classification:
        if self._inflight >= self._max_workers:
            raise ClassifierUnavailable("inference pool saturated; failing closed rather than queueing")
        self._inflight += 1
        try:
            raw = await asyncio.get_running_loop().run_in_executor(self._executor, self._predict, prompt)
        finally:
            self._inflight -= 1
        return self._translate(raw)

    def _predict(self, prompt: str) -> dict:
        with self._predict_lock:
            agent = self._load()
            return agent.predict(prompt, self._questions)

    def _translate(self, raw: dict) -> Classification:
        """Anti-corruption layer: Laya's answer shape becomes a domain `Classification`."""
        try:
            answers = raw["answers"]
            probability = float(answers[IS_MALICIOUS]["noul"])
            choice = Choice.from_value(answers[CATEGORY]["choice"])
            rubric = answers.get(RISK, {}).get("score")
        except (KeyError, TypeError, ValueError) as exc:
            raise ClassifierUnavailable(f"unparseable Laya response: {exc}") from exc
        return Classification(
            choice=choice,
            malice_probability=probability,
            rubric_score=float(rubric) if rubric is not None else None,
            vendor_confidence=None,
            backend=self.name,
        )

    async def aclose(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
