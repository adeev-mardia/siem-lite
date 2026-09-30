"""Port scan detection: a single source IP touching M+ distinct destination
ports within a sliding time window (firewall/connection log events).
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterator, Sequence

from ..events import Alert, Event, FirewallEvent
from .base import Rule


class PortScanRule(Rule):
    name = "port_scan"
    default_config = {
        "distinct_ports_threshold": 15,
        "window_seconds": 30,
    }

    def run(self, events: Sequence[Event]) -> Iterator[Alert]:
        threshold = int(self.config["distinct_ports_threshold"])
        window = timedelta(seconds=int(self.config["window_seconds"]))

        fw_events = [e for e in events if isinstance(e, FirewallEvent)]
        fw_events.sort(key=lambda e: e.timestamp)

        per_ip_window: dict[str, deque[FirewallEvent]] = defaultdict(deque)
        last_alert_end: dict[str, object] = {}

        for ev in fw_events:
            buf = per_ip_window[ev.src_ip]
            buf.append(ev)
            while buf and (ev.timestamp - buf[0].timestamp) > window:
                buf.popleft()

            distinct_ports = {e.dst_port for e in buf}
            if len(distinct_ports) >= threshold:
                last_end = last_alert_end.get(ev.src_ip)
                if last_end is None or ev.timestamp - last_end > window:
                    dst_ips = sorted({e.dst_ip for e in buf})
                    yield Alert(
                        rule=self.name,
                        severity="medium",
                        timestamp=ev.timestamp,
                        summary=(
                            f"Port scan suspected from {ev.src_ip}: "
                            f"{len(distinct_ports)} distinct destination ports in "
                            f"{window.total_seconds():.0f}s"
                        ),
                        details={
                            "src_ip": ev.src_ip,
                            "distinct_ports": len(distinct_ports),
                            "ports": sorted(distinct_ports),
                            "window_seconds": window.total_seconds(),
                            "window_start": buf[0].timestamp.isoformat(),
                            "window_end": ev.timestamp.isoformat(),
                            "targets": dst_ips,
                            "threshold": threshold,
                        },
                    )
                last_alert_end[ev.src_ip] = ev.timestamp
