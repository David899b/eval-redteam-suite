from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Decision, SuitePolicy


def render_markdown(decision: Decision, policy: SuitePolicy) -> str:
    lines = [
        "# Red-team report",
        "",
        f"**Decision: `{decision.status}`**",
        "",
        "## Attack success rate",
        "",
        f"- Overall ASR: **{decision.overall_asr:.3f}** "
        f"(95% CI {decision.ci_low:.3f}-{decision.ci_high:.3f})",
        f"- Target: overall ASR <= {policy.max_overall_asr:.2f}",
        f"- Zero tolerance on: {', '.join(policy.zero_tolerance_severities)}",
        "",
        "## By OWASP category",
        "",
        "| OWASP | category | attacks | successes | ASR | 95% CI |",
        "|---|---|---|---|---|---|",
    ]
    for c in decision.categories:
        lines.append(
            f"| {c.owasp_id} | {c.category} | {c.attacks} | {c.successes} | "
            f"{c.asr:.3f} | {c.ci_low:.2f}-{c.ci_high:.2f} |"
        )
    lines += ["", "## Rationale", ""]
    lines += [f"- {r}" for r in decision.rationale]
    lines += ["", "## Succeeded attacks", ""]
    if decision.failures:
        lines += ["| id | OWASP | severity | reason |", "|---|---|---|---|"]
        for f in decision.failures:
            lines.append(f"| {f.attack.id} | {f.attack.owasp_id} | {f.attack.severity} | {f.reason} |")
    else:
        lines.append("_No attack succeeded._")
    lines.append("")
    return "\n".join(lines)


def to_dict(decision: Decision, policy: SuitePolicy) -> dict[str, Any]:
    return {
        "status": decision.status,
        "overall_asr": decision.overall_asr,
        "ci": [decision.ci_low, decision.ci_high],
        "policy": {
            "max_overall_asr": policy.max_overall_asr,
            "zero_tolerance_severities": list(policy.zero_tolerance_severities),
        },
        "categories": [
            {
                "owasp_id": c.owasp_id,
                "category": c.category,
                "attacks": c.attacks,
                "successes": c.successes,
                "asr": c.asr,
                "ci": [c.ci_low, c.ci_high],
            }
            for c in decision.categories
        ],
        "failures": [
            {
                "id": f.attack.id,
                "owasp_id": f.attack.owasp_id,
                "severity": f.attack.severity,
                "reason": f.reason,
            }
            for f in decision.failures
        ],
        "rationale": list(decision.rationale),
    }


def write_reports(decision: Decision, policy: SuitePolicy, report_dir: str) -> tuple[Path, Path]:
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    md = out / "report.md"
    js = out / "report.json"
    md.write_text(render_markdown(decision, policy))
    js.write_text(json.dumps(to_dict(decision, policy), indent=2))
    return md, js
