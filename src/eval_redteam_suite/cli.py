from __future__ import annotations

import argparse
from collections.abc import Sequence

from .detectors import detect_success
from .gate import decide
from .loaders import load_attacks, load_target_outputs
from .models import Attack, AttackResult, SuitePolicy, TargetOutput
from .report import write_reports


def run_attacks(
    attacks: Sequence[Attack], outputs: dict[str, TargetOutput]
) -> tuple[AttackResult, ...]:
    results: list[AttackResult] = []
    for attack in attacks:
        output = outputs.get(attack.id)
        if output is None:
            continue
        succeeded, reason = detect_success(attack, output)
        results.append(AttackResult(attack=attack, succeeded=succeeded, reason=reason))
    return tuple(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eval-redteam-suite",
        description="OWASP-aligned red-team gate with an Attack Success Rate target.",
    )
    parser.add_argument("--attacks", required=True, help="path to the attack corpus (JSON)")
    parser.add_argument("--targets", required=True, help="path to the target outputs (JSON)")
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--max-overall-asr", type=float, default=0.10)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    attacks = load_attacks(args.attacks)
    outputs = load_target_outputs(args.targets)
    results = run_attacks(attacks, outputs)
    policy = SuitePolicy(max_overall_asr=args.max_overall_asr)
    decision = decide(results, policy)
    md, js = write_reports(decision, policy, args.report_dir)

    print(
        f"decision={decision.status}  overall_asr={decision.overall_asr:.3f} "
        f"(95% CI {decision.ci_low:.3f}-{decision.ci_high:.3f})"
    )
    for c in decision.categories:
        print(f"  {c.owasp_id} {c.category}: asr={c.asr:.2f} ({c.successes}/{c.attacks})")
    for f in decision.failures:
        print(f"  [BREACH] {f.attack.id} ({f.attack.severity}): {f.reason}")
    print(f"report: {md}")
    print(f"report: {js}")
    return 0 if decision.status in ("GO", "REVIEW") else 1
