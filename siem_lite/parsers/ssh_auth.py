"""Parser for SSH authentication logs in the classic syslog / auth.log style.

Handles lines like:
    Sep 30 14:22:01 webserver01 sshd[14231]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2
    Sep 30 14:22:03 webserver01 sshd[14231]: Failed password for root from 203.0.113.5 port 51516 ssh2
    Sep 30 14:22:05 webserver01 sshd[14235]: Accepted password for deploy from 10.0.0.12 port 22 ssh2
    Sep 30 14:22:06 webserver01 sshd[14236]: Accepted publickey for deploy from 10.0.0.12 port 22 ssh2
    Sep 30 14:22:08 webserver01 sshd[14240]: Invalid user oracle from 198.51.100.9 port 40011

Malformed / unrecognized lines are skipped (returned as None from
parse_ssh_line) rather than raising, so a single bad line never kills an
ingest run.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..events import SSHEvent

# syslog timestamp has no year; caller supplies one (default: current year)
_SYSLOG_TS_RE = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

_LINE_RE = re.compile(
    rf"^{_SYSLOG_TS_RE}\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.+)$"
)

_FAILED_RE = re.compile(
    r"^Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2$"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) ssh2$"
)
_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)$"
)


def parse_ssh_line(line: str, year: Optional[int] = None) -> Optional[SSHEvent]:
    """Parse one auth.log line into an SSHEvent, or None if unrecognized."""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _LINE_RE.match(line)
    if not m:
        return None
    year = year or datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
        # syslog timestamps carry no timezone; this project treats them as
        # UTC throughout so they compare directly with the other formats'
        # timezone-aware timestamps.
        ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    host = m.group("host")
    msg = m.group("msg")

    fm = _FAILED_RE.match(msg)
    if fm:
        return SSHEvent(
            timestamp=ts,
            host=host,
            action="failed_password",
            user=fm.group("user"),
            src_ip=fm.group("ip"),
            src_port=int(fm.group("port")),
            raw=line,
        )

    am = _ACCEPTED_RE.match(msg)
    if am:
        return SSHEvent(
            timestamp=ts,
            host=host,
            action="accepted_password",
            user=am.group("user"),
            src_ip=am.group("ip"),
            src_port=int(am.group("port")),
            raw=line,
        )

    im = _INVALID_USER_RE.match(msg)
    if im:
        return SSHEvent(
            timestamp=ts,
            host=host,
            action="invalid_user",
            user=im.group("user"),
            src_ip=im.group("ip"),
            src_port=int(im.group("port")),
            raw=line,
        )

    return None


def parse_ssh_file(path: str | Path, year: Optional[int] = None) -> Iterator[SSHEvent]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_ssh_line(line, year=year)
            if ev is not None:
                yield ev


def parse_ssh_lines(lines: Iterable[str], year: Optional[int] = None) -> Iterator[SSHEvent]:
    for line in lines:
        ev = parse_ssh_line(line, year=year)
        if ev is not None:
            yield ev
