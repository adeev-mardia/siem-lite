"""SQL-injection-pattern detection in access log request paths.

Uses a set of real, commonly-cited SQLi signatures (the same family of
patterns used in OWASP CRS / ModSecurity style rules), applied to the
URL-decoded request path + query string of each web access event.
"""
from __future__ import annotations

import re
from typing import Iterator, Sequence
from urllib.parse import unquote

from ..events import Alert, Event, WebAccessEvent
from .base import Rule

# Each entry: (label, compiled regex). Kept as a list of small, readable
# signatures rather than one giant regex, so alerts can report *which*
# pattern matched.
_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("union_select", re.compile(r"union\s+(all\s+)?select", re.I)),
    ("or_tautology", re.compile(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I)),
    ("or_string_tautology", re.compile(r"['\"]\s*or\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?", re.I)),
    ("comment_terminator", re.compile(r"(--|#|/\*)\s*$")),
    ("stacked_query", re.compile(r";\s*(drop|delete|insert|update)\s+", re.I)),
    ("drop_table", re.compile(r"\bdrop\s+table\b", re.I)),
    ("sleep_timing", re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.I)),
    ("benchmark_timing", re.compile(r"\bbenchmark\s*\(", re.I)),
    ("info_schema", re.compile(r"information_schema", re.I)),
    ("hex_encoded", re.compile(r"0x[0-9a-f]{6,}", re.I)),
    ("classic_quote_paren", re.compile(r"'\)|\)\s*--")),
]


class SQLiPatternRule(Rule):
    name = "sqli_pattern"
    default_config = {
        "min_status_ignore": None,  # e.g. set to 404 to skip pure 404 noise if desired
    }

    def run(self, events: Sequence[Event]) -> Iterator[Alert]:
        web_events = [e for e in events if isinstance(e, WebAccessEvent)]
        web_events.sort(key=lambda e: e.timestamp)

        for ev in web_events:
            target = unquote(ev.path)
            matched = [label for label, rx in _SIGNATURES if rx.search(target)]
            if matched:
                yield Alert(
                    rule=self.name,
                    severity="critical",
                    timestamp=ev.timestamp,
                    summary=(
                        f"Possible SQL injection attempt from {ev.src_ip} "
                        f"on {ev.method} {ev.path} (signatures: {', '.join(matched)})"
                    ),
                    details={
                        "src_ip": ev.src_ip,
                        "method": ev.method,
                        "path": ev.path,
                        "decoded_path": target,
                        "status": ev.status,
                        "signatures_matched": matched,
                    },
                )
