#!/usr/bin/env python3
"""Behavioural checks that run with the standard library only.

Used locally (no pytest/ruff/mypy installed) and in CI as a fast SCA smoke
step. The full toolchain (pytest + hypothesis + mutmut + bandit) runs in CI.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eval_redteam_suite.asr import (  # noqa: E402
    overall_asr,
    summarize_by_category,
    wilson_interval,
)
from eval_redteam_suite.cli import main as cli_main  # noqa: E402
from eval_redteam_suite.detectors import detect_success  # noqa: E402
from eval_redteam_suite.gate import decide  # noqa: E402
from eval_redteam_suite.loaders import load_attacks, load_target_outputs  # noqa: E402
from eval_redteam_suite.models import (  # noqa: E402
    Attack,
    AttackResult,
    SuitePolicy,
    TargetOutput,
)

RESULTS: list[tuple[bool, str]] = []


def check(name: str, condition: bool) -> None:
    RESULTS.append((condition, name))


def atk(**kw: object) -> Attack:
    base: dict[str, object] = {
        "id": "a",
        "owasp_id": "LLM01",
        "category": "Prompt Injection",
        "severity": "high",
        "payload": "p",
    }
    base.update(kw)
    return Attack(**base)  # type: ignore[arg-type]


def out(**kw: object) -> TargetOutput:
    base: dict[str, object] = {"attack_id": "a", "response": "ok"}
    base.update(kw)
    return TargetOutput(**base)  # type: ignore[arg-type]


def result(succeeded: bool, severity: str = "high") -> AttackResult:
    return AttackResult(atk(severity=severity), succeeded, "reason")


def main() -> int:
    # detectors
    check("marker caught", detect_success(atk(success_markers=("PWNED",)), out(response="x PWNED y"))[0])
    check("marker case-insensitive", detect_success(atk(success_markers=("pwned",)), out(response="PWNED"))[0])
    check("canary caught", detect_success(atk(canary="CANARY-1"), out(response="key CANARY-1"))[0])
    check("forbidden tool caught", detect_success(atk(forbidden_tools=("rm_db",)), out(used_tools=("rm_db",)))[0])
    check("token budget caught", detect_success(atk(max_allowed_tokens=10), out(tokens=11))[0])
    check("resistance detected", not detect_success(atk(success_markers=("PWNED",)), out(response="I refuse"))[0])

    # wilson interval
    lo, hi = wilson_interval(0, 10)
    check("wilson 0/10 low bound is 0", lo == 0.0)
    check("wilson bounds ordered", lo <= hi)
    check("wilson empty is flat", wilson_interval(0, 0) == (0.0, 0.0))
    check("wilson within [0,1]", 0.0 <= wilson_interval(5, 10)[0] <= wilson_interval(5, 10)[1] <= 1.0)

    # asr
    results = [result(True), result(False), result(False), result(False)]
    check("overall asr fractions", overall_asr(results) == 0.25)
    check("overall asr empty is 0", overall_asr([]) == 0.0)
    cats = summarize_by_category(results)
    check("category summary count", len(cats) == 1 and cats[0].attacks == 4 and cats[0].successes == 1)

    # gate
    check("gate GO on full resistance", decide([result(False)]).status == "GO")
    check("gate NO_GO on critical breach", decide([result(True, "critical")]).status == "NO_GO")
    medium = [result(True, "medium")] * 3 + [result(False)] * 18
    check("gate REVIEW on medium-only", decide(medium).status == "REVIEW")
    many = [result(True, "medium")] * 5 + [result(False)] * 5
    check("gate NO_GO when asr > 2x target", decide(many).status == "NO_GO")

    # loaders
    attacks = load_attacks(str(ROOT / "data" / "attacks.json"))
    targets = load_target_outputs(str(ROOT / "data" / "target_outputs.json"))
    check("attacks loaded", len(attacks) == 12)
    check("every attack has a target", all(a.id in targets for a in attacks))
    check(
        "targets carry token counts",
        all(t.tokens >= 0 for t in targets.values()),
    )

    # cli end-to-end (reference run -> NO_GO -> exit 1)
    with tempfile.TemporaryDirectory() as tmp:
        code = cli_main(
            [
                "--attacks",
                str(ROOT / "data" / "attacks.json"),
                "--targets",
                str(ROOT / "data" / "target_outputs.json"),
                "--report-dir",
                tmp,
            ]
        )
        check("cli exit 1 on NO_GO", code == 1)
        check("report.md written", (Path(tmp) / "report.md").exists())
        check("report.json written", (Path(tmp) / "report.json").exists())

    passed = sum(1 for ok, _ in RESULTS if ok)
    for ok, name in RESULTS:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
