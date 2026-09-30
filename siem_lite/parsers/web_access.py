"""Parser for Apache/Nginx "combined" access log format.

Real format:
    203.0.113.9 - - [30/Sep/2026:14:22:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"

Fields: remote_host, ident (-), authuser (-), [timestamp], "request line",
status, bytes, "referrer", "user-agent".
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..events import WebAccessEvent

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>HTTP/\d\.\d)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"$'
)

_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_web_line(line: str) -> Optional[WebAccessEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), _TS_FMT)
    except ValueError:
        return None
    b = m.group("bytes")
    return WebAccessEvent(
        timestamp=ts,
        src_ip=m.group("ip"),
        method=m.group("method"),
        path=m.group("path"),
        protocol=m.group("proto"),
        status=int(m.group("status")),
        bytes_sent=0 if b == "-" else int(b),
        referrer=m.group("referrer"),
        user_agent=m.group("agent"),
        raw=line,
    )


def parse_web_file(path: str | Path) -> Iterator[WebAccessEvent]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_web_line(line)
            if ev is not None:
                yield ev


def parse_web_lines(lines: Iterable[str]) -> Iterator[WebAccessEvent]:
    for line in lines:
        ev = parse_web_line(line)
        if ev is not None:
            yield ev
