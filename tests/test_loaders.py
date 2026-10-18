from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval_redteam_suite.loaders import load_attacks, load_target_outputs

ROOT = Path(__file__).resolve().parents[1]


def test_reference_corpus_loads() -> None:
    attacks = load_attacks(str(ROOT / "data" / "attacks.json"))
    targets = load_target_outputs(str(ROOT / "data" / "target_outputs.json"))
    assert len(attacks) == 12
    assert all(a.id in targets for a in attacks)


def test_duplicate_attack_id_rejected(tmp_path: Path) -> None:
    payload = {
        "attacks": [
            {"id": "dup", "owasp_id": "LLM01", "category": "c", "severity": "high", "payload": "p"},
            {"id": "dup", "owasp_id": "LLM01", "category": "c", "severity": "high", "payload": "p"},
        ]
    }
    path = tmp_path / "attacks.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="duplicate"):
        load_attacks(str(path))


def test_missing_targets_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "outputs.json"
    path.write_text(json.dumps({"outputs": []}))
    assert load_target_outputs(str(path)) == {}
