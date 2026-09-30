from siem_lite.parsers.ssh_auth import parse_ssh_line
from siem_lite.parsers.web_access import parse_web_line
from siem_lite.parsers.firewall import parse_firewall_line


def test_ssh_failed_password_invalid_user():
    line = "Sep 30 14:22:01 webserver01 sshd[14231]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    ev = parse_ssh_line(line, year=2026)
    assert ev is not None
    assert ev.action == "failed_password"
    assert ev.user == "admin"
    assert ev.src_ip == "203.0.113.5"
    assert ev.src_port == 51515
    assert ev.timestamp.month == 9 and ev.timestamp.day == 30


def test_ssh_failed_password_valid_user():
    line = "Sep 30 14:22:03 webserver01 sshd[14231]: Failed password for root from 203.0.113.5 port 51516 ssh2"
    ev = parse_ssh_line(line, year=2026)
    assert ev is not None
    assert ev.user == "root"
    assert ev.action == "failed_password"


def test_ssh_accepted_password():
    line = "Sep 30 14:22:05 webserver01 sshd[14235]: Accepted password for deploy from 10.0.0.12 port 22 ssh2"
    ev = parse_ssh_line(line, year=2026)
    assert ev is not None
    assert ev.action == "accepted_password"
    assert ev.user == "deploy"


def test_ssh_accepted_publickey():
    line = "Sep 30 14:22:06 webserver01 sshd[14236]: Accepted publickey for deploy from 10.0.0.12 port 22 ssh2"
    ev = parse_ssh_line(line, year=2026)
    assert ev is not None
    assert ev.action == "accepted_password"  # publickey normalized under same action bucket


def test_ssh_malformed_line_returns_none():
    assert parse_ssh_line("this is not a log line at all") is None
    assert parse_ssh_line("") is None
    assert parse_ssh_line("   \n") is None


def test_web_access_combined_format():
    line = '203.0.113.9 - - [30/Sep/2026:14:22:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    ev = parse_web_line(line)
    assert ev is not None
    assert ev.src_ip == "203.0.113.9"
    assert ev.method == "GET"
    assert ev.path == "/index.html"
    assert ev.status == 200
    assert ev.bytes_sent == 1024
    assert ev.user_agent == "Mozilla/5.0"


def test_web_access_dash_bytes():
    line = '203.0.113.9 - - [30/Sep/2026:14:22:01 +0000] "GET /empty HTTP/1.1" 304 - "-" "curl/8.0"'
    ev = parse_web_line(line)
    assert ev is not None
    assert ev.bytes_sent == 0


def test_web_access_malformed_returns_none():
    assert parse_web_line("not a valid access log line") is None
    assert parse_web_line("") is None


def test_firewall_line():
    line = "2026-09-30T14:22:01+00:00 SRC=203.0.113.9 DST=10.0.0.5 DPT=22 PROTO=TCP ACTION=DENY"
    ev = parse_firewall_line(line)
    assert ev is not None
    assert ev.src_ip == "203.0.113.9"
    assert ev.dst_ip == "10.0.0.5"
    assert ev.dst_port == 22
    assert ev.protocol == "TCP"
    assert ev.action == "DENY"


def test_firewall_malformed_returns_none():
    assert parse_firewall_line("garbage line with no structure") is None
    assert parse_firewall_line("SRC=1.2.3.4 missing everything else") is None
