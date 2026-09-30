"""siem-lite CLI: ingest logs, run detection rules, print/export alerts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .events import Event
from .parsers import parse_ssh_file, parse_web_file, parse_firewall_file
from .rules import Engine, load_ruleset_config, RULE_REGISTRY

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _detect_and_parse(path: Path) -> list[Event]:
    """Sniff a log file's format from its first few parseable lines and
    parse the whole file with the matching parser."""
    from .parsers.ssh_auth import parse_ssh_line
    from .parsers.web_access import parse_web_line
    from .parsers.firewall import parse_firewall_line

    sniffers = [
        ("ssh_auth", parse_ssh_line),
        ("web_access", parse_web_line),
        ("firewall", parse_firewall_line),
    ]
    with path.open("r", encoding="utf-8", errors="replace") as f:
        sample_lines = [next(f, "") for _ in range(25)]

    scores = {name: 0 for name, _ in sniffers}
    for line in sample_lines:
        if not line.strip():
            continue
        for name, fn in sniffers:
            try:
                if fn(line) is not None:
                    scores[name] += 1
            except Exception:
                pass

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        print(f"warning: could not detect log format for {path}, skipping", file=sys.stderr)
        return []

    if best == "ssh_auth":
        return list(parse_ssh_file(path))
    if best == "web_access":
        return list(parse_web_file(path))
    return list(parse_firewall_file(path))


def cmd_ingest(args: argparse.Namespace) -> int:
    all_events: list[Event] = []
    for logfile in args.logfiles:
        p = Path(logfile)
        if not p.exists():
            print(f"error: no such file: {p}", file=sys.stderr)
            return 2
        events = _detect_and_parse(p)
        print(f"parsed {len(events)} events from {p}", file=sys.stderr)
        all_events.extend(events)

    ruleset_config = load_ruleset_config(args.rules)
    engine = Engine(ruleset_config)
    alerts = engine.run(all_events)
    alerts.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.timestamp))

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([a.to_dict() for a in alerts], indent=2), encoding="utf-8"
        )
        print(f"wrote {len(alerts)} alerts -> {args.json_out}", file=sys.stderr)

    if not args.quiet:
        _print_table(alerts)

    print(f"\n{len(all_events)} events ingested, {len(alerts)} alerts generated.", file=sys.stderr)
    return 1 if alerts and args.fail_on_alert else 0


def _print_table(alerts) -> None:
    if not alerts:
        print("No alerts.")
        return
    headers = ["TIME", "SEVERITY", "RULE", "SUMMARY"]
    rows = []
    for a in alerts:
        rows.append([
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.severity.upper(),
            a.rule,
            a.summary,
        ])
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-" * len(line))
    for r in rows:
        print(" | ".join(r[i].ljust(widths[i]) for i in range(len(headers))))


def cmd_list_rules(args: argparse.Namespace) -> int:
    for name, cls in RULE_REGISTRY.items():
        print(f"{name}: {cls.default_config}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    from .generate_logs import generate
    result = generate(Path(args.outdir), seed=args.seed, hours=args.hours)
    print(f"Wrote {result['counts']['ssh']} SSH lines -> {result['auth_log']}")
    print(f"Wrote {result['counts']['web']} web lines -> {result['access_log']}")
    print(f"Wrote {result['counts']['firewall']} firewall lines -> {result['firewall_log']}")
    print(f"Ground truth -> {result['ground_truth']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siem-lite", description="A small, real log analysis / correlation engine.")
    sub = p.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Parse log file(s) and run detection rules")
    ingest.add_argument("logfiles", nargs="+", help="One or more log files (format auto-detected)")
    ingest.add_argument("--rules", default=None, help="Path to a JSON ruleset config (optional)")
    ingest.add_argument("--json-out", default=None, help="Write alerts as JSON to this path")
    ingest.add_argument("--quiet", action="store_true", help="Suppress the printed alert table")
    ingest.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alerts fired (CI use)")
    ingest.set_defaults(func=cmd_ingest)

    rules = sub.add_parser("list-rules", help="List available detection rules and their default config")
    rules.set_defaults(func=cmd_list_rules)

    gen = sub.add_parser("generate", help="Generate synthetic logs with injected attack scenarios")
    gen.add_argument("--outdir", default="data")
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--hours", type=float, default=2.0)
    gen.set_defaults(func=cmd_generate)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
