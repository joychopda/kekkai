"""Benchmark statistics, checked against inputs whose answers are known by hand."""

from __future__ import annotations

import pytest

from benchmarks.metrics import Calibration, LatencySummary, SecurityGate, percentile


@pytest.mark.parametrize("q,expected", [(0, 1.0), (50, 5.5), (100, 10.0)])
def test_percentile_endpoints_and_median(q, expected):
    assert percentile([float(i) for i in range(1, 11)], q) == pytest.approx(expected)


def test_percentile_of_empty_and_single():
    assert percentile([], 95) == 0.0
    assert percentile([42.0], 95) == 42.0


def test_latency_summary_orders_percentiles():
    summary = LatencySummary.of([float(i) for i in range(1, 101)])
    assert summary.p50 < summary.p95 < summary.p99 <= summary.max
    assert summary.count == 100


def test_a_perfectly_calibrated_predictor_has_near_zero_ece():
    """Ten predictions at p=0.1 with exactly one positive, and so on up the range."""
    probabilities: list[float] = []
    outcomes: list[bool] = []
    for tenth in range(1, 11):
        p = tenth / 10
        for i in range(10):
            probabilities.append(p)
            outcomes.append(i < tenth)
    assert Calibration.of(probabilities, outcomes).ece < 0.01


def test_a_confidently_wrong_predictor_has_ece_near_one():
    calibration = Calibration.of([0.99] * 50, [False] * 50)
    assert calibration.ece > 0.95


def test_calibration_rejects_mismatched_inputs():
    with pytest.raises(ValueError, match="same length"):
        Calibration.of([0.5], [True, False])


def test_calibration_of_nothing_is_zero_not_an_error():
    assert Calibration.of([], []).ece == 0.0


def test_the_gate_passes_only_when_both_thresholds_are_met():
    assert SecurityGate(true_positives=99, false_negatives=1, false_positives=1, true_negatives=99).passed
    assert not SecurityGate(true_positives=90, false_negatives=10, false_positives=0, true_negatives=100).passed
    assert not SecurityGate(true_positives=100, false_negatives=0, false_positives=5, true_negatives=95).passed


def test_a_gate_with_no_samples_does_not_silently_pass():
    """An empty run must not report a green gate -- that is how a broken harness ships."""
    assert not SecurityGate(0, 0, 0, 0).passed


def test_auc_of_a_perfect_separator_is_one():
    from benchmarks.metrics import roc_auc

    assert roc_auc([0.9, 0.8, 0.2, 0.1], [True, True, False, False]) == 1.0


def test_auc_of_completely_overlapping_distributions_is_half():
    """The case that distinguishes 'mistuned threshold' from 'no signal at all'."""
    from benchmarks.metrics import roc_auc

    assert roc_auc([0.5] * 20, [True] * 10 + [False] * 10) == 0.5


def test_auc_of_an_inverted_predictor_is_zero():
    from benchmarks.metrics import roc_auc

    assert roc_auc([0.1, 0.2, 0.8, 0.9], [True, True, False, False]) == 0.0


def test_auc_with_one_class_absent_is_undefined_and_reports_half():
    from benchmarks.metrics import roc_auc

    assert roc_auc([0.9, 0.8], [True, True]) == 0.5
