"""Sliding time-window logic shared by the rules.

Question it answers: "within any `window` seconds, did the count reach `threshold`?"
Consecutive/overlapping windows that all pass are merged into ONE episode, so a long scan
produces one alert instead of hundreds.
"""

from collections import Counter
from collections.abc import Hashable, Sequence
from dataclasses import dataclass


@dataclass
class Episode:
    events: list[tuple[float, Hashable]]  # every (time, value) inside the merged windows
    peak: int  # highest count reached in a single window

    @property
    def start(self) -> float:
        return self.events[0][0]

    @property
    def end(self) -> float:
        return self.events[-1][0]


def find_episodes(
    events: Sequence[tuple[float, Hashable]],
    window: float,
    threshold: int,
    distinct: bool,
) -> list[Episode]:
    """events: (timestamp, value) pairs. distinct=True counts distinct values (e.g. ports),
    distinct=False counts events (e.g. attempts)."""
    events = sorted(events, key=lambda e: e[0])
    in_window: Counter = Counter()
    total = 0
    left = 0
    ranges: list[list[int]] = []  # [first index, last index, peak]

    for right, (time, value) in enumerate(events):
        in_window[value] += 1
        total += 1
        while events[left][0] < time - window:  # drop events older than the window
            old = events[left][1]
            in_window[old] -= 1
            if in_window[old] == 0:
                del in_window[old]
            total -= 1
            left += 1

        size = len(in_window) if distinct else total
        if size < threshold:
            continue
        if ranges and left <= ranges[-1][1] + 1:  # overlaps the current episode: extend it
            ranges[-1][1] = right
            ranges[-1][2] = max(ranges[-1][2], size)
        else:
            ranges.append([left, right, size])

    return [Episode(events=list(events[a : b + 1]), peak=peak) for a, b, peak in ranges]
