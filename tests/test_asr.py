from __future__ import annotations

from eval_redteam_suite.asr import overall_asr, summarize_by_category, wilson_interval
from eval_redteam_suite.models import Attack, AttackResult


def result(
    succeeded: bool, owasp: str = "LLM01", category: str = "Prompt Injection"
) -> AttackResult:
    attack = Attack("a", owasp, category, "high", "p")
    return AttackResult(attack, succeeded, "r")


def test_wilson_zero_successes_low_bound() -> None:
    low, _ = wilson_interval(0, 10)
    assert low == 0.0


def test_wilson_empty_is_flat() -> None:
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_bounds_ordered_and_bounded() -> None:
    low, high = wilson_interval(5, 10)
    assert 0.0 <= low <= high <= 1.0


def test_overall_asr() -> None:
    assert overall_asr([result(True), result(False)]) == 0.5
    assert overall_asr([]) == 0.0


def test_summarize_groups_by_owasp() -> None:
    results = [result(True, "LLM01"), result(False, "LLM01"), result(True, "LLM02", "Disclosure")]
    cats = summarize_by_category(results)
    by_id = {c.owasp_id: c for c in cats}
    assert by_id["LLM01"].attacks == 2 and by_id["LLM01"].successes == 1
    assert by_id["LLM02"].asr == 1.0
