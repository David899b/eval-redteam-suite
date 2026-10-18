from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Attack, TargetOutput


def _items(path: str, key: str) -> list[dict[str, Any]]:
    raw: Any = json.loads(Path(path).read_text())
    items = raw[key] if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError(f"{path}: expected a list under '{key}'")
    return items


def load_attacks(path: str) -> tuple[Attack, ...]:
    out: list[Attack] = []
    seen: set[str] = set()
    for item in _items(path, "attacks"):
        attack_id = str(item["id"])
        if attack_id in seen:
            raise ValueError(f"duplicate attack id: {attack_id}")
        seen.add(attack_id)
        out.append(
            Attack(
                id=attack_id,
                owasp_id=str(item["owasp_id"]),
                category=str(item["category"]),
                severity=str(item["severity"]),
                payload=str(item["payload"]),
                success_markers=tuple(item.get("success_markers", ())),
                canary=item.get("canary"),
                forbidden_tools=tuple(item.get("forbidden_tools", ())),
                max_allowed_tokens=item.get("max_allowed_tokens"),
            )
        )
    return tuple(out)


def load_target_outputs(path: str) -> dict[str, TargetOutput]:
    result: dict[str, TargetOutput] = {}
    for item in _items(path, "outputs"):
        attack_id = str(item["attack_id"])
        result[attack_id] = TargetOutput(
            attack_id=attack_id,
            response=str(item["response"]),
            used_tools=tuple(item.get("used_tools", ())),
            tokens=int(item.get("tokens", 0)),
            latency_ms=float(item.get("latency_ms", 0.0)),
        )
    return result


def targets_for(attacks: tuple[Attack, ...], outputs: dict[str, TargetOutput]) -> dict[str, TargetOutput]:
    missing = [a.id for a in attacks if a.id not in outputs]
    if missing:
        raise ValueError(f"missing target outputs for attacks: {', '.join(missing)}")
    return outputs
