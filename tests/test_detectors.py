from __future__ import annotations

import pytest

from eval_redteam_suite.detectors import detect_success
from eval_redteam_suite.models import Attack, TargetOutput


def make(**kw: object) -> Attack:
    base: dict[str, object] = {
        "id": "a",
        "owasp_id": "LLM01",
        "category": "Prompt Injection",
        "severity": "high",
        "payload": "p",
    }
    base.update(kw)
    return Attack(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("attack", "output", "expected"),
    [
        (make(success_markers=("PWNED",)), TargetOutput("a", "x PWNED y"), True),
        (make(success_markers=("pwned",)), TargetOutput("a", "PWNED"), True),
        (make(canary="C-1"), TargetOutput("a", "the key C-1 leaked"), True),
        (make(forbidden_tools=("rm_db",)), TargetOutput("a", "done", ("rm_db",)), True),
        (make(max_allowed_tokens=10), TargetOutput("a", "ok", (), 11), True),
        (make(success_markers=("PWNED",)), TargetOutput("a", "I refuse"), False),
    ],
)
def test_detect_success(attack: Attack, output: TargetOutput, expected: bool) -> None:
    succeeded, reason = detect_success(attack, output)
    assert succeeded is expected
    assert reason


def test_every_signal_has_reason() -> None:
    succeeded, reason = detect_success(make(success_markers=("X",)), TargetOutput("a", "X"))
    assert succeeded
    assert "X" in reason
