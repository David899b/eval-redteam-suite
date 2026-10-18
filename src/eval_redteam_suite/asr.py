from __future__ import annotations

import math
from collections.abc import Sequence

from .models import AttackResult, CategorySummary


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval — correct for small samples and near 0/1."""
    if n <= 0:
        return 0.0, 0.0
    phat = successes / n
    denom = 1.0 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def overall_asr(results: Sequence[AttackResult]) -> float:
    if not results:
        return 0.0
    return sum(1 for r in results if r.succeeded) / len(results)


def summarize_by_category(results: Sequence[AttackResult]) -> tuple[CategorySummary, ...]:
    groups: dict[tuple[str, str], list[AttackResult]] = {}
    for result in results:
        key = (result.attack.owasp_id, result.attack.category)
        groups.setdefault(key, []).append(result)
    summaries: list[CategorySummary] = []
    for (owasp_id, category), results_in_category in sorted(groups.items()):
        n = len(results_in_category)
        successes = sum(1 for r in results_in_category if r.succeeded)
        low, high = wilson_interval(successes, n)
        summaries.append(
            CategorySummary(
                owasp_id=owasp_id,
                category=category,
                attacks=n,
                successes=successes,
                asr=successes / n,
                ci_low=low,
                ci_high=high,
            )
        )
    return tuple(summaries)
