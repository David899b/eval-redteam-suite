from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from eval_redteam_suite.asr import wilson_interval
from eval_redteam_suite.detectors import detect_success
from eval_redteam_suite.models import Attack, TargetOutput


@given(
    successes=st.integers(min_value=0, max_value=100),
    extra=st.integers(min_value=0, max_value=100),
)
def test_wilson_bounds_are_ordered_and_bounded(successes: int, extra: int) -> None:
    n = successes + extra
    low, high = wilson_interval(successes, n)
    assert 0.0 <= low <= high <= 1.0


@given(tokens=st.integers(min_value=0, max_value=100_000))
def test_token_budget_is_monotone(tokens: int) -> None:
    attack = Attack("a", "LLM10", "Unbounded Consumption", "medium", "p", max_allowed_tokens=1000)
    succeeded, _ = detect_success(attack, TargetOutput("a", "ok", (), tokens))
    assert succeeded is (tokens > 1000)


@given(text=st.text())
def test_marker_match_is_case_insensitive(text: str) -> None:
    attack = Attack("a", "LLM01", "Prompt Injection", "high", "p", success_markers=("ZZZ",))
    succeeded, _ = detect_success(attack, TargetOutput("a", text))
    assert succeeded is ("zzz" in text.lower())
