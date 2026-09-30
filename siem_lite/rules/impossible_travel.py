"""Anomalous account usage: the same username authenticating (or attempting
to authenticate) from many distinct source IPs within a short window.

This is a simplified stand-in for "impossible travel" detection used by
real identity/SIEM products (which use geo-IP distance/time deltas) — here
we use distinct-source-IP fan-out per username within a window, which is a
genuinely useful correlation signal on its own (credential sharing,
credential-stuffing against one account, compromised laptop + VPN churn).
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterator, Sequence

from ..events import Alert, Event, SSHEvent
from .base import Rule


class ImpossibleTravelRule(Rule):
    name = "anomalous_account_fanout"
    default_config = {
        "distinct_ip_threshold": 4,
        "window_seconds": 300,
        "include_actions": ("accepted_password", "failed_password"),
    }

    def run(self, events: Sequence[Event]) -> Iterator[Alert]:
        threshold = int(self.config["distinct_ip_threshold"])
        window = timedelta(seconds=int(self.config["window_seconds"]))
        include_actions = set(self.config["include_actions"])

        ssh_events = [
            e for e in events if isinstance(e, SSHEvent) and e.action in include_actions
        ]
        ssh_events.sort(key=lambda e: e.timestamp)

        per_user_window: dict[str, deque[SSHEvent]] = defaultdict(deque)
        last_alert_end: dict[str, object] = {}

        for ev in ssh_events:
            buf = per_user_window[ev.user]
            buf.append(ev)
            while buf and (ev.timestamp - buf[0].timestamp) > window:
                buf.popleft()

            distinct_ips = {e.src_ip for e in buf}
            if len(distinct_ips) >= threshold:
                last_end = last_alert_end.get(ev.user)
                if last_end is None or ev.timestamp - last_end > window:
                    yield Alert(
                        rule=self.name,
                        severity="medium",
                        timestamp=ev.timestamp,
                        summary=(
                            f"Account '{ev.user}' seen from {len(distinct_ips)} "
                            f"distinct source IPs within {window.total_seconds():.0f}s"
                        ),
                        details={
                            "user": ev.user,
                            "distinct_ips": sorted(distinct_ips),
                            "ip_count": len(distinct_ips),
                            "window_seconds": window.total_seconds(),
                            "window_start": buf[0].timestamp.isoformat(),
                            "window_end": ev.timestamp.isoformat(),
                            "threshold": threshold,
                        },
                    )
                last_alert_end[ev.user] = ev.timestamp
