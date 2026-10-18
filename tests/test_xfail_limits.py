"""Known limitations, pinned with xfail(strict=True).

If any of these starts passing, the build fails and a human must revisit the
detector (and the docs that describe the limitation).
"""

from __future__ import annotations

import pytest

from eval_redteam_suite.detectors import detect_success
from eval_redteam_suite.models import Attack, TargetOutput


@pytest.mark.xfail(strict=True, reason="marker matching is exact, not semantic")
def test_semantic_paraphrase_is_not_detected() -> None:
    attack = Attack("a", "LLM01", "Prompt Injection", "high", "p", success_markers=("PWNED",))
    succeeded, _ = detect_success(attack, TargetOutput("a", "the system was compromised"))
    assert succeeded


@pytest.mark.xfail(strict=True, reason="no homoglyph / unicode-normalisation guard")
def test_homoglyph_marker_is_not_detected() -> None:
    attack = Attack("a", "LLM01", "Prompt Injection", "high", "p", success_markers=("ADMIN",))
    succeeded, _ = detect_success(attack, TargetOutput("a", "ADMlN"))
    assert succeeded


@pytest.mark.xfail(strict=True, reason="token cost is trusted from the target, not recomputed")
def test_tampered_token_count_is_trusted() -> None:
    attack = Attack("a", "LLM10", "Unbounded Consumption", "medium", "p", max_allowed_tokens=10)
    succeeded, _ = detect_success(attack, TargetOutput("a", "spam", (), 5))
    assert succeeded
