"""Benchmark one or more backends against the versioned threat dataset.

Reports latency percentiles, Expected Calibration Error, and the safety gates, split by the
dataset's two bands. The split matters: the deterministic band is resolved by the rule layer
before a backend is consulted, so scores there are identical for every backend and say nothing
about which is better. The ambiguous band is the comparison.

Promotion is safety-gated, not speed-gated: a backend that misses the block-rate or
false-positive threshold cannot be promoted however fast it is.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.metrics import Calibration, LatencySummary, SecurityGate, roc_auc  # noqa: E402
from kekkai.adapters.audit_sink import MemoryAuditSink  # noqa: E402
from kekkai.adapters.classifiers import get_backend  # noqa: E402
from kekkai.adapters.envelope_builder import build_envelope  # noqa: E402
from kekkai.application.cache import DecisionCache  # noqa: E402
from kekkai.application.errors import ClassifierUnavailable  # noqa: E402
from kekkai.application.ports import ClassifierPort  # noqa: E402
from kekkai.application.screen_tool_call import ScreenToolCall  # noqa: E402
from kekkai.domain.policy import ScreeningPolicy  # noqa: E402
from kekkai.domain.prefilter import SessionSnapshot  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "tests" / "fixtures" / "threat_dataset.json"
LEDGER = Path(__file__).resolve().parent / "results" / "ledger.jsonl"
ALLOWLIST = frozenset({"api.github.com", "docs.python.org"})

#: Jev bills per input token, so an unbounded sweep is real money. Every live run states the
#: request budget it used.
JEV_USD_PER_MILLION_INPUT_TOKENS = 0.042


@dataclass
class Observation:
    record_id: str
    band: str
    split: str
    malicious: bool
    blocked: bool
    probability: float
    latency_ms: float
    classifier_latency_ms: float
    consulted: bool
    failed_closed: bool
    prompt_chars: int


def _relative(path: Path) -> Path:
    """Path relative to the repo root where possible, so reports travel."""
    try:
        return path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return path


def load_records(path: Path, limit: int = 0) -> list[dict]:
    records = json.loads(path.read_text(encoding="utf-8"))["records"]
    return records[:limit] if limit else records


class TimedClassifier(ClassifierPort):
    """Wraps a backend to record per-call latency without touching the interactor."""

    def __init__(self, inner: ClassifierPort):
        self.inner = inner
        self.name = inner.name
        self.tier = inner.tier
        self.samples: list[float] = []
        self.calls = 0
        self.failures = 0
        self.prompt_chars = 0

    async def classify(self, prompt: str, *, deadline_ms: float):
        self.calls += 1
        self.prompt_chars += len(prompt)
        started = time.perf_counter()
        try:
            return await self.inner.classify(prompt, deadline_ms=deadline_ms)
        except ClassifierUnavailable:
            self.failures += 1
            raise
        finally:
            self.samples.append((time.perf_counter() - started) * 1000)

    async def warmup(self) -> None:
        await self.inner.warmup()

    async def aclose(self) -> None:
        await self.inner.aclose()


async def sweep(backend_name: str, records: list[dict], *, policy: ScreeningPolicy, **backend_kwargs) -> dict:
    inner = get_backend(backend_name)(**backend_kwargs)
    classifier = TimedClassifier(inner)
    await classifier.warmup()

    use_case = ScreenToolCall(
        classifier,
        MemoryAuditSink(),
        policy=policy,
        workspace_root="/proj",
        egress_allowlist=ALLOWLIST,
        # A one-entry cache, effectively disabled: a cache hit would measure the cache rather
        # than the backend, and every record here is distinct anyway.
        cache=DecisionCache(1),
    )

    observations: list[Observation] = []
    for record in records:
        before_calls = classifier.calls
        before_samples = len(classifier.samples)
        envelope = build_envelope(record["tool_name"], record["args"], session_id="bench")
        started = time.perf_counter()
        result = await use_case.screen(envelope, SessionSnapshot(session_id=f"bench-{record['id']}"))
        elapsed = (time.perf_counter() - started) * 1000
        consulted = classifier.calls > before_calls
        classifier_ms = 0.0
        if consulted and len(classifier.samples) > before_samples:
            classifier_ms = classifier.samples[before_samples]
        observations.append(
            Observation(
                record_id=record["id"],
                band=record["band"],
                split=record["split"],
                malicious=record["label"] == "malicious",
                blocked=result.blocked,
                probability=result.malice_probability,
                latency_ms=elapsed,
                classifier_latency_ms=classifier_ms,
                consulted=consulted,
                failed_closed=result.failed_closed,
                prompt_chars=len(envelope.classifier_prompt()[0]),
            )
        )

    await classifier.aclose()
    return summarize(backend_name, observations, classifier, policy, backend_kwargs)


def _gate(observations: list[Observation]) -> SecurityGate:
    return SecurityGate(
        true_positives=sum(1 for o in observations if o.malicious and o.blocked),
        false_negatives=sum(1 for o in observations if o.malicious and not o.blocked),
        false_positives=sum(1 for o in observations if not o.malicious and o.blocked),
        true_negatives=sum(1 for o in observations if not o.malicious and not o.blocked),
    )


def summarize(
    backend_name: str,
    observations: list[Observation],
    classifier: TimedClassifier,
    policy: ScreeningPolicy,
    backend_kwargs: dict,
) -> dict:
    consulted = [o for o in observations if o.consulted]
    ambiguous = [o for o in observations if o.band == "ambiguous"]
    deterministic = [o for o in observations if o.band == "deterministic"]
    held_out = [o for o in ambiguous if o.split == "test"]

    # ECE is computed only where a backend actually answered. Including short-circuited calls
    # would score the rule layer's certainty as though it were the model's.
    calibration = Calibration.of([o.probability for o in consulted], [o.malicious for o in consulted])

    estimated_tokens = classifier.prompt_chars / 4  # ~4 chars/token, the usual rule of thumb
    deadline_ms = (
        policy.classifier_deadline_ms if classifier.tier.value == "common" else policy.escalated_deadline_ms
    )
    return {
        "backend": backend_name,
        "backend_options": {k: v for k, v in backend_kwargs.items() if v is not None},
        "tier": classifier.tier.value,
        "records": len(observations),
        "classifier_calls": classifier.calls,
        "classifier_failures": classifier.failures,
        "short_circuited": len(observations) - len(consulted),
        "end_to_end_latency": LatencySummary.of([o.latency_ms for o in observations]).to_dict(),
        "classifier_latency": LatencySummary.of(classifier.samples).to_dict(),
        "short_circuit_latency": LatencySummary.of(
            [o.latency_ms for o in observations if not o.consulted]
        ).to_dict(),
        "calibration": calibration.to_dict(),
        "discrimination_auc": round(
            roc_auc([o.probability for o in consulted], [o.malicious for o in consulted]), 4
        ),
        "gates": {
            "overall": _gate(observations).to_dict(),
            "deterministic_band": _gate(deterministic).to_dict(),
            "ambiguous_band": _gate(ambiguous).to_dict(),
            "ambiguous_band_holdout": _gate(held_out).to_dict(),
        },
        "deadline_ms": deadline_ms,
        "deadline_exceeded_calls": sum(1 for s in classifier.samples if s > deadline_ms),
        "estimated_input_tokens": int(estimated_tokens),
        "estimated_cost_usd": round(estimated_tokens / 1_000_000 * JEV_USD_PER_MILLION_INPUT_TOKENS, 6)
        if backend_name == "jev"
        else 0.0,
    }


def render(report: dict) -> str:
    lines = [
        "",
        f"  host: {report['host']['platform']}  python {report['host']['python']}",
        f"  dataset: {report['dataset']['records']} records "
        f"({report['dataset']['ambiguous_band']} ambiguous)  policy deadline: "
        f"{report['policy']['classifier_deadline_ms']:.0f}ms common / "
        f"{report['policy']['escalated_deadline_ms']:.0f}ms escalated",
        "",
        f"  {'backend@deadline':<22}{'p50':>9}{'p95':>9}{'p99':>9}{'ECE':>9}{'AUC':>8}{'block':>9}{'FPR':>8}"
        f"{'timeouts':>10}  gate",
        "  " + "-" * 100,
    ]
    for entry in report["backends"]:
        ambiguous = entry["gates"]["ambiguous_band"]
        latency = entry["classifier_latency"]
        gate = "PASS" if ambiguous["passed"] else "FAIL"
        label = entry["backend"]
        if entry["backend_options"].get("device"):
            label = f"{label}/{entry['backend_options']['device']}"
        label = f"{label}@{entry['deadline_ms']:.0f}ms"
        timeouts = entry["deadline_exceeded_calls"]
        share = timeouts / entry["classifier_calls"] * 100 if entry["classifier_calls"] else 0.0
        lines.append(
            f"  {label:<22}{latency['p50_ms']:>8.1f}ms{latency['p95_ms']:>8.1f}ms{latency['p99_ms']:>8.1f}ms"
            f"{entry['calibration']['ece']:>9.3f}{entry['discrimination_auc']:>8.3f}"
            f"{ambiguous['block_rate'] * 100:>8.1f}%"
            f"{ambiguous['false_positive_rate'] * 100:>7.1f}%{share:>9.0f}%  {gate}"
        )
    lines.extend(
        [
            "",
            "  block rate and FPR are on the AMBIGUOUS band only: the deterministic band is",
            "  resolved before any backend is consulted, so it scores identically for all of them.",
            "",
        ]
    )
    return "\n".join(lines)


def main(args: argparse.Namespace) -> int:
    dataset_path = Path(args.dataset) if getattr(args, "dataset", None) else DATASET
    records = load_records(dataset_path, getattr(args, "limit", 0) or 0)
    policy = ScreeningPolicy.default()

    requested = [b.strip() for b in args.backends.split(",") if b.strip()]
    deadlines = [float(d) for d in str(args.deadlines).split(",") if str(d).strip()]
    entries = []
    for deadline in deadlines:
        # The deadline is a benchmark axis, not a constant. The spec's 100 ms is a T4-GPU
        # figure; whether a backend can meet it on the host actually running it is one of the
        # things this suite exists to measure.
        run_policy = ScreeningPolicy(
            classifier_deadline_ms=deadline,
            common_deadline_ms=max(deadline + 5.0, policy.common_deadline_ms),
            escalated_deadline_ms=max(deadline, policy.escalated_deadline_ms),
        )
        for spec in requested:
            name, _, device = spec.partition("/")
            kwargs = {"device": device} if device else {}
            try:
                entries.append(asyncio.run(sweep(name, records, policy=run_policy, **kwargs)))
            except (KeyError, ClassifierUnavailable) as exc:
                entries.append({"backend": spec, "error": f"{type(exc).__name__}: {exc}"})

    successes = [e for e in entries if "error" not in e]
    failures = [e for e in entries if "error" in e]
    report: dict = {
        "generated_at": time.time(),
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "dataset": {
            # Relative to the repo root. These reports are committed and read by people on
            # other machines; an absolute path would be noise at best and a stranger's
            # home directory at worst.
            "path": str(_relative(dataset_path)),
            "records": len(records),
            "ambiguous_band": sum(1 for r in records if r["band"] == "ambiguous"),
        },
        "policy": {
            "block_threshold": policy.block_threshold,
            "classifier_deadline_ms": policy.classifier_deadline_ms,
            "escalated_deadline_ms": policy.escalated_deadline_ms,
        },
        "backends": successes,
        "errors": failures,
    }

    print(render(report))
    for failure in failures:
        print(f"  {failure['backend']}: {failure['error']}")

    out = Path(args.out) if getattr(args, "out", None) else None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"  report written to {out}")

    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8") as fh:
        command = " ".join([str(_relative(Path(sys.argv[0]))), *sys.argv[1:]])
        fh.write(json.dumps({"command": command, "report": report}) + "\n")

    return 0 if successes else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--backends",
        default="replay",
        help="comma-separated; append /device for laya, e.g. laya/mps",
    )
    parser.add_argument("--dataset")
    parser.add_argument("--out")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument(
        "--deadlines",
        default="95",
        help="comma-separated classifier deadlines in ms to sweep (default: the policy's 95)",
    )
    parser.add_argument("--replay", action="store_true")
    return parser


if __name__ == "__main__":
    sys.exit(main(build_parser().parse_args()))
