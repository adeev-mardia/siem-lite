"""Synthetic multi-format log generator with injected attack scenarios and
known ground truth.

Produces three files in the given output directory:
    auth.log       - SSH auth log (syslog format)
    access.log     - Apache/Nginx combined access log
    firewall.log   - simple connection log

...plus a ground_truth.json describing exactly what was injected (scenario
name, time window, source IPs, counts) so detection output can be checked
against it.

Usage:
    python -m siem_lite.generate_logs --outdir data --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

USERS = ["deploy", "www-data", "root", "ubuntu", "admin", "jenkins", "backup"]
INVALID_USERS = ["oracle", "postgres", "test", "guest", "administrator", "pi", "git"]
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
]
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/products/42",
    "/api/v1/health", "/login", "/static/app.css", "/static/app.js",
    "/favicon.ico", "/blog/2026-09-hello-world",
]
SQLI_PAYLOADS = [
    "/products?id=1' OR '1'='1",
    "/search?q=test' UNION SELECT username,password FROM users--",
    "/login?user=admin'--",
    "/products?id=1 AND 1=1",
    "/items?id=5; DROP TABLE users;",
    "/api/v1/user?id=1 OR 1=1",
    "/search?q=1' AND SLEEP(5)--",
]


def _rand_ip(rng: random.Random, private=False) -> str:
    if private:
        return f"10.0.0.{rng.randint(2, 60)}"
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _fmt_syslog(ts: datetime) -> str:
    # syslog day-of-month is space-padded, not zero-padded (e.g. "Sep  3")
    day = f"{ts.day:2d}"
    return f"{ts.strftime('%b')} {day} {ts.strftime('%H:%M:%S')}"


def _fmt_apache(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S %z")


def generate(outdir: Path, seed: int = 42, hours: float = 2.0):
    rng = random.Random(seed)
    start = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(hours=hours)
    host = "prod-web01"

    ssh_lines: list[tuple[datetime, str]] = []
    web_lines: list[tuple[datetime, str]] = []
    fw_lines: list[tuple[datetime, str]] = []

    ground_truth: dict = {"scenarios": []}

    # ---- 1. Normal background SSH logins (legit admins) ----
    t = start
    while t < end:
        t += timedelta(seconds=rng.randint(180, 900))
        if t >= end:
            break
        user = rng.choice(USERS)
        ip = _rand_ip(rng, private=True)
        port = rng.randint(30000, 60000)
        ssh_lines.append((t, f"{_fmt_syslog(t)} {host} sshd[{rng.randint(1000,9999)}]: Accepted password for {user} from {ip} port {port} ssh2"))

    # occasional single failed login (typo), not a brute force
    for _ in range(6):
        t = start + timedelta(seconds=rng.randint(0, int(hours * 3600)))
        user = rng.choice(USERS)
        ip = _rand_ip(rng, private=True)
        port = rng.randint(30000, 60000)
        ssh_lines.append((t, f"{_fmt_syslog(t)} {host} sshd[{rng.randint(1000,9999)}]: Failed password for {user} from {ip} port {port} ssh2"))

    # ---- 2. Injected SSH brute-force burst ----
    bf_start = start + timedelta(minutes=37, seconds=12)
    bf_ip = "203.0.113.77"
    bf_count = 22
    bf_end = bf_start
    for i in range(bf_count):
        t = bf_start + timedelta(seconds=i * 2)
        bf_end = t
        user = rng.choice(INVALID_USERS)
        port = rng.randint(40000, 65000)
        ssh_lines.append((t, f"{_fmt_syslog(t)} {host} sshd[{rng.randint(1000,9999)}]: Failed password for invalid user {user} from {bf_ip} port {port} ssh2"))
    ground_truth["scenarios"].append({
        "name": "ssh_brute_force",
        "src_ip": bf_ip,
        "attempt_count": bf_count,
        "window": [bf_start.isoformat(), bf_end.isoformat()],
        "expected_rule": "ssh_brute_force",
    })

    # ---- 3. Injected account fan-out (same user, many source IPs) ----
    fanout_user = "jenkins"
    fanout_start = start + timedelta(minutes=55)
    fanout_ips = [_rand_ip(rng) for _ in range(6)]
    for i, ip in enumerate(fanout_ips):
        t = fanout_start + timedelta(seconds=i * 20)
        port = rng.randint(40000, 60000)
        action = "Accepted password" if i % 2 == 0 else "Failed password"
        ssh_lines.append((t, f"{_fmt_syslog(t)} {host} sshd[{rng.randint(1000,9999)}]: {action} for {fanout_user} from {ip} port {port} ssh2"))
    ground_truth["scenarios"].append({
        "name": "account_fanout",
        "user": fanout_user,
        "distinct_ips": len(fanout_ips),
        "ips": fanout_ips,
        "window": [fanout_start.isoformat(), (fanout_start + timedelta(seconds=20 * len(fanout_ips))).isoformat()],
        "expected_rule": "anomalous_account_fanout",
    })

    # ---- 4. Normal background web traffic ----
    t = start
    while t < end:
        t += timedelta(seconds=rng.randint(1, 20))
        if t >= end:
            break
        ip = _rand_ip(rng)
        path = rng.choice(NORMAL_PATHS)
        status = rng.choice([200, 200, 200, 200, 304, 404])
        size = rng.randint(200, 40000)
        ua = rng.choice(NORMAL_USER_AGENTS)
        web_lines.append((t, f'{ip} - - [{_fmt_apache(t)}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'))

    # ---- 5. Injected SQLi probing burst ----
    sqli_start = start + timedelta(minutes=20)
    sqli_ip = "198.51.100.23"
    sqli_events = 0
    for i, payload in enumerate(SQLI_PAYLOADS):
        t = sqli_start + timedelta(seconds=i * 4)
        status = rng.choice([200, 500, 403])
        # real HTTP requests can't contain literal spaces in the request
        # line; a real attacker's client (browser or sqlmap) URL-encodes
        # them, so we do the same here to keep the access log well-formed.
        encoded_payload = quote(payload, safe="/?=&;")
        web_lines.append((t, f'{sqli_ip} - - [{_fmt_apache(t)}] "GET {encoded_payload} HTTP/1.1" {status} {rng.randint(100,900)} "-" "sqlmap/1.7"'))
        sqli_events += 1
    ground_truth["scenarios"].append({
        "name": "sqli_probe",
        "src_ip": sqli_ip,
        "request_count": sqli_events,
        "window": [sqli_start.isoformat(), (sqli_start + timedelta(seconds=4 * len(SQLI_PAYLOADS))).isoformat()],
        "expected_rule": "sqli_pattern",
    })

    # ---- 6. Normal background firewall ALLOW traffic ----
    t = start
    while t < end:
        t += timedelta(seconds=rng.randint(2, 15))
        if t >= end:
            break
        src = _rand_ip(rng, private=True)
        dst = "10.0.0.5"
        dport = rng.choice([80, 443, 22, 5432])
        fw_lines.append((t, f"{t.isoformat()} SRC={src} DST={dst} DPT={dport} PROTO=TCP ACTION=ALLOW"))

    # ---- 7. Injected port scan ----
    scan_start = start + timedelta(minutes=10)
    scan_ip = "192.0.2.44"
    scan_ports = rng.sample(range(1, 65000), 40)
    scan_end = scan_start
    for i, p in enumerate(scan_ports):
        t = scan_start + timedelta(milliseconds=i * 500)
        scan_end = t
        action = "DENY" if p not in (22, 80, 443) else "ALLOW"
        fw_lines.append((t, f"{t.isoformat()} SRC={scan_ip} DST=10.0.0.5 DPT={p} PROTO=TCP ACTION={action}"))
    ground_truth["scenarios"].append({
        "name": "port_scan",
        "src_ip": scan_ip,
        "distinct_ports": len(set(scan_ports)),
        "window": [scan_start.isoformat(), scan_end.isoformat()],
        "expected_rule": "port_scan",
    })

    # sort and write files
    ssh_lines.sort(key=lambda x: x[0])
    web_lines.sort(key=lambda x: x[0])
    fw_lines.sort(key=lambda x: x[0])

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "auth.log").write_text("\n".join(l for _, l in ssh_lines) + "\n", encoding="utf-8")
    (outdir / "access.log").write_text("\n".join(l for _, l in web_lines) + "\n", encoding="utf-8")
    (outdir / "firewall.log").write_text("\n".join(l for _, l in fw_lines) + "\n", encoding="utf-8")
    (outdir / "ground_truth.json").write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")

    return {
        "auth_log": outdir / "auth.log",
        "access_log": outdir / "access.log",
        "firewall_log": outdir / "firewall.log",
        "ground_truth": outdir / "ground_truth.json",
        "counts": {"ssh": len(ssh_lines), "web": len(web_lines), "firewall": len(fw_lines)},
    }


def main():
    ap = argparse.ArgumentParser(description="Generate synthetic multi-format SIEM logs with injected attacks.")
    ap.add_argument("--outdir", default="data", help="Output directory")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hours", type=float, default=2.0)
    args = ap.parse_args()

    result = generate(Path(args.outdir), seed=args.seed, hours=args.hours)
    print(f"Wrote {result['counts']['ssh']} SSH lines -> {result['auth_log']}")
    print(f"Wrote {result['counts']['web']} web lines -> {result['access_log']}")
    print(f"Wrote {result['counts']['firewall']} firewall lines -> {result['firewall_log']}")
    print(f"Ground truth -> {result['ground_truth']}")


if __name__ == "__main__":
    main()
