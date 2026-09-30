"""Base class + shared sliding-window helper for detection rules."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Sequence

from ..events import Alert, Event


class Rule(ABC):
    """A pluggable detection rule.

    Subclasses implement `run`, which receives the FULL chronologically
    sorted event stream and yields Alerts. Rules are stateless between
    calls to `run` (a fresh instance / fresh internal state each run), so
    results are always computed live from whatever events are passed in.
    """

    name: str = "base_rule"
    default_config: dict = {}

    def __init__(self, config: dict | None = None):
        merged = dict(self.default_config)
        if config:
            merged.update(config)
        self.config = merged

    @abstractmethod
    def run(self, events: Sequence[Event]) -> Iterator[Alert]:
        raise NotImplementedError


def sliding_window_groups(
    timestamped_items: Iterable[tuple[datetime, object]],
    window: timedelta,
):
    """Yield (window_end_ts, items_in_window) for every point where an item
    enters the window, using a two-pointer sliding window over items that
    are already sorted by timestamp ascending.

    `timestamped_items` must be an iterable of (timestamp, payload) sorted
    by timestamp. This is O(n) amortized.
    """
    buf: deque[tuple[datetime, object]] = deque()
    for ts, payload in timestamped_items:
        buf.append((ts, payload))
        while buf and (ts - buf[0][0]) > window:
            buf.popleft()
        yield ts, list(buf)
