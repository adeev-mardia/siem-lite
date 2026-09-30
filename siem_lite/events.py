"""Structured event models produced by every parser.

All parsers normalize their source format into one of these dataclasses so
the rules engine can operate on a single unified stream regardless of which
log format an event originated from.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SSHEvent:
    timestamp: datetime
    host: str
    action: str  # "failed_password" | "accepted_password" | "invalid_user" | "other"
    user: str
    src_ip: str
    src_port: Optional[int]
    raw: str
    source_format: str = "ssh_auth"


@dataclass
class WebAccessEvent:
    timestamp: datetime
    src_ip: str
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referrer: str
    user_agent: str
    raw: str
    source_format: str = "web_access"


@dataclass
class FirewallEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    action: str  # "ALLOW" | "DENY"
    raw: str
    source_format: str = "firewall"


# Union type used by the engine
Event = SSHEvent | WebAccessEvent | FirewallEvent


@dataclass
class Alert:
    rule: str
    severity: str  # "low" | "medium" | "high" | "critical"
    timestamp: datetime
    summary: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary,
            "details": self.details,
        }
        return d
