"""Latency percentiles, calibration error, and the safety gates.

Kept separate from the runner so the statistics can be unit-tested against known inputs
rather than trusted because the numbers look plausible.
"""

from __future__ import annotations

from dataclasses import dataclass


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile. `q` in [0, 100].

    Written out rather than pulled from numpy so the benchmark runs with no dependencies --
    the same reason the core package has none.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (q / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


@dataclass(frozen=True)
class LatencySummary:
    count: int
    p50: float
    p95: float
    p99: float
    mean: float
    max: float

    @classmethod
    def of(cls, samples: list[float]) -> LatencySummary:
        if not samples:
            return cls(0, 0.0, 0.0, 0.0, 0.0, 0.0)
        return cls(
            count=len(samples),
            p50=percentile(samples, 50),
            p95=percentile(samples, 95),
            p99=percentile(samples, 99),
            mean=sum(samples) / len(samples),
            max=max(samples),
        )

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "p50_ms": round(self.p50, 3),
            "p95_ms": round(self.p95, 3),
            "p99_ms": round(self.p99, 3),
            "mean_ms": round(self.mean, 3),
            "max_ms": round(self.max, 3),
        }


@dataclass(frozen=True)
class CalibrationBin:
    lower: float
    upper: float
    count: int
    mean_confidence: float
    observed_frequency: float


@dataclass(frozen=True)
class Calibration:
    """Expected Calibration Error over predicted probabilities.

    Computed on the malice probability -- the value the 0.85 threshold actually reads -- and
    never on a backend's self-reported `confidence`. TypeSafe states, and the vLLM
    semantic-router evaluation restates, that Jev's confidence is not a label probability;
    computing ECE from it would produce a number that looks like calibration and is not.
    """

    ece: float
    max_error: float
    bins: tuple[CalibrationBin, ...]
    samples: int

    @classmethod
    def of(cls, probabilities: list[float], outcomes: list[bool], *, n_bins: int = 10) -> Calibration:
        if len(probabilities) != len(outcomes):
            raise ValueError("probabilities and outcomes must be the same length")
        if not probabilities:
            return cls(0.0, 0.0, (), 0)

        total = len(probabilities)
        bins: list[CalibrationBin] = []
        ece = 0.0
        worst = 0.0
        for index in range(n_bins):
            lower = index / n_bins
            upper = (index + 1) / n_bins
            members = [
                (p, o)
                for p, o in zip(probabilities, outcomes, strict=True)
                if (p > lower or (index == 0 and p >= 0.0)) and p <= upper
            ]
            if not members:
                bins.append(CalibrationBin(lower, upper, 0, 0.0, 0.0))
                continue
            mean_confidence = sum(p for p, _ in members) / len(members)
            frequency = sum(1 for _, o in members if o) / len(members)
            gap = abs(mean_confidence - frequency)
            ece += (len(members) / total) * gap
            worst = max(worst, gap)
            bins.append(CalibrationBin(lower, upper, len(members), mean_confidence, frequency))
        return cls(ece=ece, max_error=worst, bins=tuple(bins), samples=total)

    def to_dict(self) -> dict:
        return {
            "ece": round(self.ece, 5),
            "max_bin_error": round(self.max_error, 5),
            "samples": self.samples,
            "bins": [
                {
                    "range": f"{b.lower:.1f}-{b.upper:.1f}",
                    "n": b.count,
                    "mean_p": round(b.mean_confidence, 4),
                    "observed": round(b.observed_frequency, 4),
                }
                for b in self.bins
            ],
        }


def roc_auc(probabilities: list[float], outcomes: list[bool]) -> float:
    """Probability that a random malicious payload scores above a random benign one.

    This is the question a threshold cannot answer for you: ECE says whether a probability
    means what it claims, and block rate and FPR say how one particular cutoff performs, but
    only discrimination says whether *any* cutoff could work. An AUC near 0.5 means the two
    distributions overlap, and no choice of threshold separates them -- so a poor gate result
    is the model having no signal on the task, not the threshold being mistuned.

    Computed by rank (the Mann-Whitney U form), with ties credited half, so it needs no
    dependencies and handles the tied scores that a saturating model produces.
    """
    positives = [p for p, o in zip(probabilities, outcomes, strict=True) if o]
    negatives = [p for p, o in zip(probabilities, outcomes, strict=True) if not o]
    if not positives or not negatives:
        return 0.5
    wins = 0.0
    for p in positives:
        for n in negatives:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


@dataclass(frozen=True)
class SecurityGate:
    """Block rate on malicious payloads, false-positive rate on safe ones."""

    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    min_block_rate: float = 0.98
    max_false_positive_rate: float = 0.02

    @property
    def block_rate(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total else 0.0

    @property
    def passed(self) -> bool:
        return self.block_rate >= self.min_block_rate and self.false_positive_rate <= self.max_false_positive_rate

    def to_dict(self) -> dict:
        return {
            "block_rate": round(self.block_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "tp": self.true_positives,
            "fn": self.false_negatives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "min_block_rate": self.min_block_rate,
            "max_false_positive_rate": self.max_false_positive_rate,
            "passed": self.passed,
        }
