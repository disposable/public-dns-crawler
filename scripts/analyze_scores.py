#!/usr/bin/env python3
"""Analyze score distribution from validation results JSON.

Usage:
    python -m scripts.analyze_scores outputs/results.json
    python -m scripts.analyze_scores outputs/results.json --compare-with outputs/old_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_results(path: str) -> list[dict[str, Any]]:
    """Load validation results from JSON file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_score_histogram(results: list[dict[str, Any]]) -> dict[int, int]:
    """Compute histogram of scores."""
    histogram: dict[int, int] = {}
    for r in results:
        score = r.get("score", 0)
        histogram[score] = histogram.get(score, 0) + 1
    return histogram


def analyze_score_distribution(
    results: list[dict[str, Any]],
    title: str = "Results",
) -> dict[str, Any]:
    """Analyze score distribution and return metrics."""
    if not results:
        return {"error": "No results to analyze"}

    total = len(results)
    accepted = [r for r in results if r.get("status") == "accepted"]
    candidates = [r for r in results if r.get("status") == "candidate"]
    rejected = [r for r in results if r.get("status") == "rejected"]

    scores = [r.get("score", 0) for r in results]
    scores_100 = sum(1 for s in scores if s == 100)
    scores_95_99 = sum(1 for s in scores if 95 <= s <= 99)
    scores_85_94 = sum(1 for s in scores if 85 <= s <= 94)
    scores_70_84 = sum(1 for s in scores if 70 <= s <= 84)
    scores_below_70 = sum(1 for s in scores if s < 70)

    # Collect reasons by score band
    reasons_by_band: dict[str, Counter] = {
        "95-99": Counter(),
        "85-94": Counter(),
        "70-84": Counter(),
        "<70": Counter(),
    }

    for r in results:
        score = r.get("score", 0)
        reasons = r.get("reasons", [])

        if 95 <= score <= 99:
            band = "95-99"
        elif 85 <= score <= 94:
            band = "85-94"
        elif 70 <= score <= 84:
            band = "70-84"
        elif score < 70:
            band = "<70"
        else:
            continue

        for reason in reasons:
            reasons_by_band[band][reason] += 1

    # Collect derived metrics correlation
    p50_values = []
    p95_values = []
    jitter_values = []
    history_values = []

    for r in results:
        derived = r.get("derived_metrics", {})
        score = r.get("score", 0)

        if derived.get("p50_latency_ms") is not None:
            p50_values.append((score, derived["p50_latency_ms"]))
        if derived.get("p95_latency_ms") is not None:
            p95_values.append((score, derived["p95_latency_ms"]))
        if derived.get("jitter_ms") is not None:
            jitter_values.append((score, derived["jitter_ms"]))
        if derived.get("runs_seen_30d") is not None:
            history_values.append((score, derived["runs_seen_30d"]))

    # Compute correlations (simple average by score band)
    def avg_by_band(
        values: list[tuple[int, float]], bands: list[tuple[int, int]]
    ) -> dict[str, float]:
        result: dict[str, list[float]] = {f"{b[0]}-{b[1]}": [] for b in bands}
        for score, val in values:
            for low, high in bands:
                if low <= score <= high:
                    result[f"{low}-{high}"].append(val)
                    break
        return {band: sum(vals) / len(vals) if vals else 0.0 for band, vals in result.items()}

    score_bands = [(95, 100), (85, 94), (70, 84), (0, 69)]

    return {
        "title": title,
        "total": total,
        "status_counts": {
            "accepted": len(accepted),
            "candidate": len(candidates),
            "rejected": len(rejected),
        },
        "score_distribution": {
            "100": scores_100,
            "95-99": scores_95_99,
            "85-94": scores_85_94,
            "70-84": scores_70_84,
            "<70": scores_below_70,
        },
        "percentage_100_of_accepted": (100.0 * scores_100 / len(accepted) if accepted else 0.0),
        "top_reasons_by_band": {
            band: reasons.most_common(5) if reasons else []
            for band, reasons in reasons_by_band.items()
        },
        "latency_correlation": {
            "p50_avg_by_score": avg_by_band(p50_values, score_bands),
            "p95_avg_by_score": avg_by_band(p95_values, score_bands),
            "jitter_avg_by_score": avg_by_band(jitter_values, score_bands),
        },
        "history_correlation": {
            "runs_seen_30d_avg_by_score": avg_by_band(history_values, score_bands),
        },
        "confidence_stats": {
            "avg_confidence": sum(r.get("confidence_score", 0) for r in results) / total
            if total
            else 0.0,
            "with_confidence": sum(1 for r in results if r.get("confidence_score", 0) > 0),
        },
        "caps_applied": Counter(
            cap for r in results for cap in r.get("score_caps_applied", [])
        ).most_common(10),
    }


def print_analysis(analysis: dict[str, Any]) -> None:
    """Print formatted analysis results."""
    print(f"\n{'=' * 60}")
    print(f"Score Distribution Analysis: {analysis.get('title', 'Unknown')}")
    print(f"{'=' * 60}")

    if "error" in analysis:
        print(f"Error: {analysis['error']}")
        return

    print(f"\nTotal resolvers: {analysis['total']}")
    print(f"Status breakdown: {analysis['status_counts']}")

    print(f"\n{'─' * 40}")
    print("Score Distribution:")
    print(f"{'─' * 40}")
    dist = analysis["score_distribution"]
    total = analysis["total"]
    for band, count in dist.items():
        pct = 100.0 * count / total if total else 0.0
        bar = "█" * int(pct / 2)
        print(f"  Score {band:>5}: {count:>4} ({pct:>5.1f}%) {bar}")

    print(f"\n  % of accepted at 100: {analysis['percentage_100_of_accepted']:.1f}%")

    print(f"\n{'─' * 40}")
    print("Top Reasons by Score Band:")
    print(f"{'─' * 40}")
    for band, reasons in analysis["top_reasons_by_band"].items():
        if reasons:
            print(f"\n  {band}:")
            for reason, count in reasons:
                print(f"    - {reason}: {count}")

    print(f"\n{'─' * 40}")
    print("Latency vs Score Correlation:")
    print(f"{'─' * 40}")
    corr = analysis["latency_correlation"]
    print("  Avg p50 latency (ms) by score:")
    for band, avg in corr["p50_avg_by_score"].items():
        if avg > 0:
            print(f"    Score {band}: {avg:.1f} ms")
    print("  Avg p95 latency (ms) by score:")
    for band, avg in corr["p95_avg_by_score"].items():
        if avg > 0:
            print(f"    Score {band}: {avg:.1f} ms")

    print(f"\n{'─' * 40}")
    print("History vs Score Correlation:")
    print(f"{'─' * 40}")
    hist = analysis["history_correlation"]
    print("  Avg runs_seen_30d by score:")
    for band, avg in hist["runs_seen_30d_avg_by_score"].items():
        if avg > 0:
            print(f"    Score {band}: {avg:.1f} runs")

    print(f"\n{'─' * 40}")
    print("Confidence Statistics:")
    print(f"{'─' * 40}")
    conf = analysis["confidence_stats"]
    print(f"  Average confidence: {conf['avg_confidence']:.1f}")
    print(f"  Resolvers with confidence data: {conf['with_confidence']}")

    print(f"\n{'─' * 40}")
    print("Most Common Score Caps Applied:")
    print(f"{'─' * 40}")
    for cap, count in analysis["caps_applied"]:
        print(f"  - {cap}: {count}")


def compare_analyses(old: dict[str, Any], new: dict[str, Any]) -> None:
    """Print comparison between two analyses."""
    print(f"\n{'=' * 60}")
    print("Before vs After Comparison")
    print(f"{'=' * 60}")

    old_dist = old.get("score_distribution", {})
    new_dist = new.get("score_distribution", {})

    print("\nScore Distribution Changes:")
    print(f"{'─' * 40}")
    for band in ["100", "95-99", "85-94", "70-84", "<70"]:
        old_count = old_dist.get(band, 0)
        new_count = new_dist.get(band, 0)
        delta = new_count - old_count
        delta_pct = old["total"] and (100.0 * delta / old["total"])
        symbol = "↑" if delta > 0 else "↓" if delta < 0 else "→"
        print(
            f"  Score {band:>5}: {old_count:>4} → {new_count:>4} "
            f"({symbol}{abs(delta):>3}, {delta_pct:>+.1f}%)"
        )

    old_pct_100 = old.get("percentage_100_of_accepted", 0)
    new_pct_100 = new.get("percentage_100_of_accepted", 0)
    print(
        f"\n  % accepted at 100: {old_pct_100:.1f}% → {new_pct_100:.1f}% "
        f"({new_pct_100 - old_pct_100:+.1f}pp)"
    )

    print("\nTarget Outcomes:")
    print(f"{'─' * 40}")
    if new_pct_100 < old_pct_100:
        print("  ✓ Fewer 100s (as intended)")
    if new_dist.get("85-94", 0) + new_dist.get("95-99", 0) > old_dist.get(
        "85-94", 0
    ) + old_dist.get("95-99", 0):
        print("  ✓ Wider spread in 85-99 range")
    print("  (Verify: poor tail-latency resolvers no longer clustered at top)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze resolver score distribution from validation results"
    )
    parser.add_argument("results_file", help="Path to validation results JSON")
    parser.add_argument(
        "--compare-with",
        dest="compare",
        help="Path to previous results JSON for comparison",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output JSON file for analysis results",
    )

    args = parser.parse_args()

    if not Path(args.results_file).exists():
        print(f"Error: File not found: {args.results_file}", file=sys.stderr)
        return 1

    results = load_results(args.results_file)
    analysis = analyze_score_distribution(results, title=args.results_file)
    print_analysis(analysis)

    if args.compare:
        if not Path(args.compare).exists():
            print(f"Error: Comparison file not found: {args.compare}", file=sys.stderr)
            return 1
        old_results = load_results(args.compare)
        old_analysis = analyze_score_distribution(old_results, title=args.compare)
        compare_analyses(old_analysis, analysis)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2)
        print(f"\nAnalysis written to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
