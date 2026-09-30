"""Parser for a simple iptables-style connection log.

Format (space-separated key=value pairs, similar to Linux kernel netfilter
LOG output, simplified for readability):

    2026-09-30T14:22:01+00:00 SRC=203.0.113.9 DST=10.0.0.5 DPT=22 PROTO=TCP ACTION=DENY
    2026-09-30T14:22:02+00:00 SRC=10.0.0.7 DST=10.0.0.5 DPT=443 PROTO=TCP ACTION=ALLOW
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..events import FirewallEvent

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+SRC=(?P<src>[0-9a-fA-F:.]+)\s+DST=(?P<dst>[0-9a-fA-F:.]+)\s+"
    r"DPT=(?P<dport>\d+)\s+PROTO=(?P<proto>\S+)\s+ACTION=(?P<action>ALLOW|DENY)\s*$"
)


def parse_firewall_line(line: str) -> Optional[FirewallEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _LINE_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.fromisoformat(m.group("ts"))
    except ValueError:
        return None
    return FirewallEvent(
        timestamp=ts,
        src_ip=m.group("src"),
        dst_ip=m.group("dst"),
        dst_port=int(m.group("dport")),
        protocol=m.group("proto"),
        action=m.group("action"),
        raw=line,
    )


def parse_firewall_file(path: str | Path) -> Iterator[FirewallEvent]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_firewall_line(line)
            if ev is not None:
                yield ev


def parse_firewall_lines(lines: Iterable[str]) -> Iterator[FirewallEvent]:
    for line in lines:
        ev = parse_firewall_line(line)
        if ev is not None:
            yield ev
