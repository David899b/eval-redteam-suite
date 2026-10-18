from __future__ import annotations

from pathlib import Path

from eval_redteam_suite.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_reference_run_is_no_go(tmp_path: Path) -> None:
    code = main(
        [
            "--attacks",
            str(ROOT / "data" / "attacks.json"),
            "--targets",
            str(ROOT / "data" / "target_outputs.json"),
            "--report-dir",
            str(tmp_path),
        ]
    )
    assert code == 1
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()


def test_max_asr_flag_does_not_change_breach_decision(tmp_path: Path) -> None:
    code = main(
        [
            "--attacks",
            str(ROOT / "data" / "attacks.json"),
            "--targets",
            str(ROOT / "data" / "target_outputs.json"),
            "--report-dir",
            str(tmp_path),
            "--max-overall-asr",
            "0.99",
        ]
    )
    assert code == 1
