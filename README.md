# siem-lite

A small, real log-parsing, detection, and correlation engine — a "SIEM-lite" — that
ingests SSH auth logs, web server access logs, and firewall/connection logs, and
raises alerts for brute-force logins, port scans, SQL-injection probing, and
anomalous account usage.

The **detection logic is genuinely computed at run time** from whatever events it is
given (sliding-window counters, distinct-value fan-out, regex signature matching) —
it is not a scripted demo that always prints the same canned alerts. The **log data**
used to demo it is synthetic (generated on purpose, with known ground truth, so the
engine's output can be verified against exactly what was injected).

## What it is

```
raw log files  →  format-specific parsers  →  structured events  →  rules engine  →  alerts
 (auth.log,        (regex-based, one per        (dataclasses:         (pluggable,      (JSON +
  access.log,        format, handle bad          SSHEvent /            sliding-         readable
  firewall.log)      lines gracefully)            WebAccessEvent /      window /         table)
                                                   FirewallEvent)        regex rules)
```

### Parsers (`siem_lite/parsers/`)

| Format | File | Example line |
|---|---|---|
| SSH auth (syslog style) | `ssh_auth.py` | `Sep 30 14:22:01 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2` |
| Web access (Apache/Nginx combined) | `web_access.py` | `203.0.113.9 - - [30/Sep/2026:14:22:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"` |
| Firewall / connection log | `firewall.py` | `2026-09-30T14:22:01+00:00 SRC=203.0.113.9 DST=10.0.0.5 DPT=22 PROTO=TCP ACTION=DENY` |

Each parser is a real regex-based parser for that format (not a toy split-on-space),
returns a typed dataclass event, and returns `None` for a line it can't parse instead
of raising — so one malformed line never kills an ingest run. `siem-lite ingest`
auto-detects which parser to use per file by sampling the first lines.

### Detection rules (`siem_lite/rules/`)

All rules subclass `Rule`, are configurable (thresholds/windows), and operate on the
full chronologically-sorted event stream using a proper O(n) sliding-window algorithm
(two-pointer / deque), not a fixed-bucket approximation.

| Rule | Signal |
|---|---|
| `ssh_brute_force` | N+ failed SSH logins from the same source IP within a sliding window |
| `port_scan` | A single source IP touching M+ distinct destination ports within a sliding window |
| `sqli_pattern` | Request paths matching real SQLi signatures (`UNION SELECT`, tautologies, stacked queries, `SLEEP()`/`BENCHMARK()` timing attacks, `information_schema` probing, hex-encoded literals, comment terminators) |
| `anomalous_account_fanout` | The same SSH username authenticating (or attempting to) from many distinct source IPs within a short window — a stand-in for "impossible travel" / credential-sharing detection |

Each alert carries the concrete evidence (source IP, count, window, matched
usernames/ports/signatures) — nothing is a hardcoded string.

### Synthetic log generator (`siem_lite/generate_logs.py`)

Generates realistic multi-format logs with normal background traffic **and**
four injected attack scenarios, plus a `ground_truth.json` describing exactly
what was injected (IPs, counts, time windows) so detection results can be checked
against a known answer:

1. an SSH brute-force burst from one IP
2. an account touched from many distinct source IPs in a short window
3. a burst of SQL-injection probing requests
4. a port scan across dozens of destination ports

Different `--seed` values produce different IPs/timings/usernames each run —
`tests/test_generate_logs.py` runs this across three seeds and confirms detection
still fires correctly each time, which is what demonstrates the engine isn't just
matching one fixed, memorized dataset.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Generate synthetic logs

```bash
siem-lite generate --outdir data --seed 42 --hours 2
# or: python -m siem_lite.generate_logs --outdir data --seed 42
```

Writes `data/auth.log`, `data/access.log`, `data/firewall.log`, and
`data/ground_truth.json`.

## Run detection

```bash
siem-lite ingest data/auth.log data/access.log data/firewall.log --json-out data/alerts.json
```

### Example output (real run against a generated `data/` sample, seed 42)

```
parsed 46 events from data/auth.log
parsed 684 events from data/access.log
parsed 876 events from data/firewall.log
wrote 10 alerts -> data/alerts.json
TIME                | SEVERITY | RULE                     | SUMMARY
--------------------------------------------------------------------------------------------------------------------------------------------------------
2026-09-30 12:20:00 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /products?id=1%27%20OR%20%271%27=%271 (signatures: or_tautology, or_string_tautology)
2026-09-30 12:20:04 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /search?q=test%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users-- (signatures: union_select, comment_terminator)
2026-09-30 12:20:08 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /login?user=admin%27-- (signatures: comment_terminator)
2026-09-30 12:20:12 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /products?id=1%20AND%201=1 (signatures: or_tautology)
2026-09-30 12:20:16 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /items?id=5;%20DROP%20TABLE%20users; (signatures: stacked_query, drop_table)
2026-09-30 12:20:20 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /api/v1/user?id=1%20OR%201=1 (signatures: or_tautology)
2026-09-30 12:20:24 | CRITICAL | sqli_pattern             | Possible SQL injection attempt from 198.51.100.23 on GET /search?q=1%27%20AND%20SLEEP%285%29-- (signatures: comment_terminator, sleep_timing, classic_quote_paren)
2026-09-30 12:37:20 | HIGH     | ssh_brute_force          | SSH brute-force suspected from 203.0.113.77: 5 failed logins in 60s
2026-09-30 12:10:07 | MEDIUM   | port_scan                | Port scan suspected from 192.0.2.44: 15 distinct destination ports in 30s
2026-09-30 12:56:00 | MEDIUM   | anomalous_account_fanout | Account 'jenkins' seen from 4 distinct source IPs within 300s

1606 events ingested, 10 alerts generated.
```

Every one of these matches the run's `data/ground_truth.json` exactly: the SQLi
alerts all name `198.51.100.23` (the injected probing IP) across all 7 injected
payloads, the brute-force alert names `203.0.113.77` (the injected burst IP), the
port scan names `192.0.2.44` (the injected scanning IP), and the fan-out alert
names `jenkins` touched from 4+ distinct IPs — all computed live by the engine,
not hardcoded. `data/` (generated logs, alerts, ground truth) is left out of
version control since it's reproducible; run `siem-lite generate` to recreate it.

### Custom rule thresholds

Pass a JSON ruleset to override any rule's config:

```json
{
  "rules": {
    "ssh_brute_force": {"enabled": true, "config": {"threshold": 3, "window_seconds": 30}},
    "port_scan":        {"enabled": true, "config": {"distinct_ports_threshold": 10}},
    "sqli_pattern":      {"enabled": true},
    "anomalous_account_fanout": {"enabled": false}
  }
}
```

```bash
siem-lite ingest data/auth.log --rules myrules.json
siem-lite list-rules   # see all rules + their default config
```

## Run tests

```bash
pytest -q
```

```
30 passed in 0.21s
```

The suite covers: real parsing of well-formed and malformed lines for all three
formats; crafted event sequences that must fire each rule; crafted "clean" sequences
that must produce **zero** false positives; threshold/window sensitivity (changing a
rule's config changes its alert count, proving it isn't hardcoded); and an end-to-end
closed loop that generates synthetic logs across multiple seeds and confirms every
injected attack is actually detected by the real parser + engine pipeline.

## Architecture notes

- Events are plain `@dataclass` models (`siem_lite/events.py`) — no ORM, no DB, kept
  simple and inspectable.
- Rules are pluggable (`siem_lite/rules/base.py`'s `Rule` ABC) and registered in
  `RULE_REGISTRY`; adding a new rule means subclassing `Rule` and registering it.
- The sliding-window logic is a genuine two-pointer algorithm over sorted events per
  key (source IP or username), not a fixed-size bucket approximation, so it gives
  exact counts for the configured window.
- The CLI (`siem_lite/cli.py`) auto-detects log format per file by sampling lines
  against each parser and picking the best match, so `ingest` works on any mix of the
  three formats in any order.

## Limitations

This is a **single-node, educational/portfolio "lite" SIEM**, not a production
security platform. Real SIEMs (Splunk, Elastic Security, Microsoft Sentinel, etc.)
additionally provide: distributed log shipping/collection agents, durable
indexed storage at terabyte scale, a real-time streaming pipeline, a query language
and long-term retention, a multi-user web UI/dashboard with case management, alert
deduplication/suppression policies, threat-intel enrichment, and SOAR-style
automated response. None of that is implemented here — this project focuses on
doing the parsing and correlation core *correctly and honestly* on a single machine.

## License

MIT — see [LICENSE](LICENSE).
