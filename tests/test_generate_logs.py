"""Verifies the synthetic generator's ground truth is actually detected by
the real engine — the closed-loop check that alerts aren't hardcoded."""
import json
from pathlib import Path

from siem_lite.generate_logs import generate
from siem_lite.parsers import parse_ssh_file, parse_web_file, parse_firewall_file
from siem_lite.rules import Engine


def test_generated_logs_are_parseable_and_detected(tmp_path: Path):
    result = generate(tmp_path, seed=123, hours=1.5)
    gt = json.loads(result["ground_truth"].read_text())

    events = []
    events += list(parse_ssh_file(result["auth_log"]))
    events += list(parse_web_file(result["access_log"]))
    events += list(parse_firewall_file(result["firewall_log"]))

    engine = Engine()
    alerts = engine.run(events)
    fired_rules = {a.rule for a in alerts}

    expected_rules = {s["expected_rule"] for s in gt["scenarios"]}
    assert expected_rules.issubset(fired_rules)

    # spot-check the brute-force alert actually names the injected IP
    bf_scenario = next(s for s in gt["scenarios"] if s["name"] == "ssh_brute_force")
    bf_alerts = [a for a in alerts if a.rule == "ssh_brute_force"]
    assert any(a.details["src_ip"] == bf_scenario["src_ip"] for a in bf_alerts)

    scan_scenario = next(s for s in gt["scenarios"] if s["name"] == "port_scan")
    scan_alerts = [a for a in alerts if a.rule == "port_scan"]
    assert any(a.details["src_ip"] == scan_scenario["src_ip"] for a in scan_alerts)


def test_different_seeds_produce_different_but_still_detected_attacks(tmp_path: Path):
    """Confirms detection isn't hardcoded to one fixed dataset: different
    seeds move IPs/timings around and the engine still finds them."""
    from siem_lite.rules import Engine as E

    for seed in (1, 2, 3):
        outdir = tmp_path / f"seed{seed}"
        result = generate(outdir, seed=seed, hours=1.0)
        events = []
        events += list(parse_ssh_file(result["auth_log"]))
        events += list(parse_web_file(result["access_log"]))
        events += list(parse_firewall_file(result["firewall_log"]))
        alerts = E().run(events)
        fired = {a.rule for a in alerts}
        assert "ssh_brute_force" in fired
        assert "port_scan" in fired
        assert "sqli_pattern" in fired
