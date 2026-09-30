from datetime import datetime, timedelta, timezone

from siem_lite.events import SSHEvent, WebAccessEvent, FirewallEvent
from siem_lite.rules import (
    BruteForceSSHRule,
    PortScanRule,
    SQLiPatternRule,
    ImpossibleTravelRule,
    Engine,
)

BASE = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)


def ssh(offset_s, action, user, ip, port=40000):
    return SSHEvent(
        timestamp=BASE + timedelta(seconds=offset_s),
        host="h", action=action, user=user, src_ip=ip, src_port=port, raw="",
    )


def web(offset_s, ip, path, status=200):
    return WebAccessEvent(
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=ip, method="GET", path=path, protocol="HTTP/1.1",
        status=status, bytes_sent=100, referrer="-", user_agent="-", raw="",
    )


def fw(offset_s, src, dst, port, action="ALLOW"):
    return FirewallEvent(
        timestamp=BASE + timedelta(seconds=offset_s),
        src_ip=src, dst_ip=dst, dst_port=port, protocol="TCP", action=action, raw="",
    )


# ---------------- Brute force ----------------

def test_brute_force_fires_on_burst():
    events = [ssh(i * 2, "failed_password", "admin", "9.9.9.9") for i in range(6)]
    rule = BruteForceSSHRule({"threshold": 5, "window_seconds": 60})
    alerts = list(rule.run(events))
    assert len(alerts) == 1
    assert alerts[0].details["src_ip"] == "9.9.9.9"
    assert alerts[0].details["failure_count"] >= 5


def test_brute_force_no_alert_below_threshold():
    events = [ssh(i * 2, "failed_password", "admin", "9.9.9.9") for i in range(3)]
    rule = BruteForceSSHRule({"threshold": 5, "window_seconds": 60})
    alerts = list(rule.run(events))
    assert alerts == []


def test_brute_force_ignores_successful_logins():
    events = [ssh(i * 2, "accepted_password", "admin", "9.9.9.9") for i in range(10)]
    rule = BruteForceSSHRule({"threshold": 5, "window_seconds": 60})
    assert list(rule.run(events)) == []


def test_brute_force_scales_with_different_thresholds():
    """Verify counts/thresholds are computed live, not hardcoded."""
    events = [ssh(i * 2, "failed_password", "admin", "9.9.9.9") for i in range(6)]
    low = list(BruteForceSSHRule({"threshold": 3, "window_seconds": 60}).run(events))
    high = list(BruteForceSSHRule({"threshold": 20, "window_seconds": 60}).run(events))
    assert len(low) >= 1
    assert len(high) == 0  # never reaches 20 failures


def test_brute_force_window_boundary_excludes_old_events():
    # two events 120s apart, window is 60s -> should never both be counted
    events = [ssh(0, "failed_password", "admin", "1.1.1.1")] + [
        ssh(120 + i * 2, "failed_password", "admin", "1.1.1.1") for i in range(4)
    ]
    rule = BruteForceSSHRule({"threshold": 5, "window_seconds": 60})
    assert list(rule.run(events)) == []  # only 4 within any 60s window, threshold 5


def test_brute_force_separate_ips_dont_combine():
    events = [ssh(i * 2, "failed_password", "admin", f"1.1.1.{i}") for i in range(6)]
    rule = BruteForceSSHRule({"threshold": 5, "window_seconds": 60})
    assert list(rule.run(events)) == []  # 6 different source IPs, no single IP crosses threshold


# ---------------- Port scan ----------------

def test_port_scan_fires_on_distinct_ports():
    events = [fw(i, "6.6.6.6", "10.0.0.1", 1000 + i) for i in range(20)]
    rule = PortScanRule({"distinct_ports_threshold": 15, "window_seconds": 30})
    alerts = list(rule.run(events))
    assert len(alerts) == 1
    assert alerts[0].details["src_ip"] == "6.6.6.6"
    assert alerts[0].details["distinct_ports"] >= 15


def test_port_scan_no_alert_for_repeated_single_port():
    events = [fw(i, "6.6.6.6", "10.0.0.1", 443) for i in range(50)]
    rule = PortScanRule({"distinct_ports_threshold": 15, "window_seconds": 30})
    assert list(rule.run(events)) == []


def test_port_scan_threshold_changes_alert_count():
    events = [fw(i, "6.6.6.6", "10.0.0.1", 1000 + i) for i in range(20)]
    loose = list(PortScanRule({"distinct_ports_threshold": 5, "window_seconds": 30}).run(events))
    strict = list(PortScanRule({"distinct_ports_threshold": 30, "window_seconds": 30}).run(events))
    assert len(loose) >= 1
    assert len(strict) == 0


# ---------------- SQLi ----------------

def test_sqli_detects_union_select():
    events = [web(0, "7.7.7.7", "/search?q=1%27%20UNION%20SELECT%20user%2Cpass%20FROM%20t--")]
    alerts = list(SQLiPatternRule().run(events))
    assert len(alerts) == 1
    assert "union_select" in alerts[0].details["signatures_matched"]


def test_sqli_detects_or_tautology():
    events = [web(0, "7.7.7.7", "/login?u=admin%27%20OR%20%271%27=%271")]
    alerts = list(SQLiPatternRule().run(events))
    assert len(alerts) == 1


def test_sqli_no_false_positive_on_normal_traffic():
    events = [
        web(0, "8.8.8.8", "/"),
        web(1, "8.8.8.8", "/products/42"),
        web(2, "8.8.8.8", "/api/v1/health"),
        web(3, "8.8.8.8", "/static/app.js"),
    ]
    assert list(SQLiPatternRule().run(events)) == []


def test_sqli_count_matches_injected_payloads():
    payloads = [
        "/a?id=1%27%20OR%20%271%27=%271",
        "/b?q=x%27%20UNION%20SELECT%20a%2Cb%20FROM%20t--",
        "/c?id=5;%20DROP%20TABLE%20users;",
    ]
    events = [web(i, "7.7.7.7", p) for i, p in enumerate(payloads)]
    alerts = list(SQLiPatternRule().run(events))
    assert len(alerts) == 3  # one alert per malicious request, count tracks input


# ---------------- Impossible travel / account fan-out ----------------

def test_account_fanout_fires():
    events = [ssh(i * 20, "accepted_password", "svc", f"5.5.5.{i}") for i in range(5)]
    rule = ImpossibleTravelRule({"distinct_ip_threshold": 4, "window_seconds": 300})
    alerts = list(rule.run(events))
    assert len(alerts) == 1
    assert alerts[0].details["user"] == "svc"
    assert alerts[0].details["ip_count"] >= 4


def test_account_fanout_no_alert_single_ip():
    events = [ssh(i * 20, "accepted_password", "svc", "5.5.5.5") for i in range(10)]
    rule = ImpossibleTravelRule({"distinct_ip_threshold": 4, "window_seconds": 300})
    assert list(rule.run(events)) == []


def test_account_fanout_different_users_dont_combine():
    events = [ssh(i * 20, "accepted_password", f"user{i}", f"5.5.5.{i}") for i in range(5)]
    rule = ImpossibleTravelRule({"distinct_ip_threshold": 4, "window_seconds": 300})
    assert list(rule.run(events)) == []


# ---------------- Engine integration ----------------

def test_engine_runs_all_rules_and_finds_nothing_on_clean_data():
    events = [
        ssh(0, "accepted_password", "deploy", "10.0.0.5"),
        ssh(30, "accepted_password", "ops", "10.0.0.6"),
        web(0, "10.0.0.7", "/"),
        web(1, "10.0.0.8", "/about"),
        fw(0, "10.0.0.9", "10.0.0.1", 443),
        fw(1, "10.0.0.9", "10.0.0.1", 443),
    ]
    engine = Engine()
    assert engine.run(events) == []


def test_engine_detects_multiple_simultaneous_attacks():
    events = []
    events += [ssh(i * 2, "failed_password", "root", "9.9.9.9") for i in range(10)]
    events += [fw(i, "6.6.6.6", "10.0.0.1", 1000 + i) for i in range(20)]
    events += [web(0, "7.7.7.7", "/x?id=1%27%20UNION%20SELECT%20a%2Cb%20FROM%20t--")]
    engine = Engine()
    alerts = engine.run(events)
    rules_fired = {a.rule for a in alerts}
    assert "ssh_brute_force" in rules_fired
    assert "port_scan" in rules_fired
    assert "sqli_pattern" in rules_fired
