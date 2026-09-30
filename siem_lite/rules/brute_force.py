"""SSH brute-force detection: N+ failed logins from the same source IP
within a sliding time window.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterator, Sequence

from ..events import Alert, Event, SSHEvent
from .base import Rule

_FAILURE_ACTIONS = {"failed_password", "invalid_user"}


class BruteForceSSHRule(Rule):
    name = "ssh_brute_force"
    default_config = {
        "threshold": 5,       # failures needed to trigger
        "window_seconds": 60, # sliding window size
    }

    def run(self, events: Sequence[Event]) -> Iterator[Alert]:
        threshold = int(self.config["threshold"])
        window = timedelta(seconds=int(self.config["window_seconds"]))

        ssh_failures = [
            e for e in events if isinstance(e, SSHEvent) and e.action in _FAILURE_ACTIONS
        ]
        ssh_failures.sort(key=lambda e: e.timestamp)

        per_ip_window: dict[str, deque[SSHEvent]] = defaultdict(deque)
        last_alert_end: dict[str, object] = {}

        for ev in ssh_failures:
            buf = per_ip_window[ev.src_ip]
            buf.append(ev)
            while buf and (ev.timestamp - buf[0].timestamp) > window:
                buf.popleft()

            if len(buf) >= threshold:
                last_end = last_alert_end.get(ev.src_ip)
                # only re-alert once the previous burst's window has fully
                # elapsed, so one sustained burst produces one alert instead
                # of one per event past the threshold
                if last_end is None or ev.timestamp - last_end > window:
                    users = sorted({e.user for e in buf})
                    yield Alert(
                        rule=self.name,
                        severity="high",
                        timestamp=ev.timestamp,
                        summary=(
                            f"SSH brute-force suspected from {ev.src_ip}: "
                            f"{len(buf)} failed logins in "
                            f"{window.total_seconds():.0f}s"
                        ),
                        details={
                            "src_ip": ev.src_ip,
                            "failure_count": len(buf),
                            "window_seconds": window.total_seconds(),
                            "window_start": buf[0].timestamp.isoformat(),
                            "window_end": ev.timestamp.isoformat(),
                            "usernames_tried": users,
                            "threshold": threshold,
                        },
                    )
                last_alert_end[ev.src_ip] = ev.timestamp
