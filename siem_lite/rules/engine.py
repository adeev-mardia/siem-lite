"""The correlation engine: runs a configured set of rules over a stream of
parsed events and returns all resulting alerts, sorted by time.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ..events import Alert, Event
from .base import Rule
from .brute_force import BruteForceSSHRule
from .port_scan import PortScanRule
from .sqli import SQLiPatternRule
from .impossible_travel import ImpossibleTravelRule

RULE_REGISTRY: dict[str, type[Rule]] = {
    BruteForceSSHRule.name: BruteForceSSHRule,
    PortScanRule.name: PortScanRule,
    SQLiPatternRule.name: SQLiPatternRule,
    ImpossibleTravelRule.name: ImpossibleTravelRule,
}


def default_ruleset_config() -> dict:
    return {
        "rules": {
            name: {"enabled": True, "config": {}} for name in RULE_REGISTRY
        }
    }


def load_ruleset_config(path: str | Path | None) -> dict:
    if path is None:
        return default_ruleset_config()
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        user_cfg = json.load(f)
    cfg = default_ruleset_config()
    for name, override in user_cfg.get("rules", {}).items():
        if name not in RULE_REGISTRY:
            raise ValueError(f"Unknown rule in ruleset config: {name}")
        cfg["rules"].setdefault(name, {"enabled": True, "config": {}})
        cfg["rules"][name].update(override)
    return cfg


class Engine:
    def __init__(self, ruleset_config: dict | None = None):
        self.ruleset_config = ruleset_config or default_ruleset_config()
        self.rules: list[Rule] = []
        for name, spec in self.ruleset_config["rules"].items():
            if not spec.get("enabled", True):
                continue
            rule_cls = RULE_REGISTRY[name]
            self.rules.append(rule_cls(spec.get("config", {})))

    def run(self, events: Sequence[Event]) -> list[Alert]:
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.run(sorted_events))
        alerts.sort(key=lambda a: a.timestamp)
        return alerts
