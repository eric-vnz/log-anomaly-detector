"""Detection rules built on parsed log records.

Each rule scans the records and returns a list of alerts. An alert describes
evidence found within a time window — it does not claim an attack occurred.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Alert:
    rule: str
    client_ip: str | None
    start: object
    end: object
    count: int
    threshold: int
    lines: tuple


def _scan_windows(sorted_records, window_seconds, threshold):
    """Scan records chronologically and yield distinct, non-overlapping alerts."""
    alerts = []
    i = 0
    n = len(sorted_records)

    while i < n:
        start_time = sorted_records[i].timestamp
        end_limit = start_time + timedelta(seconds=window_seconds)

        # Gather all events within this window
        j = i
        while j < n and sorted_records[j].timestamp < end_limit:
            j += 1

        window_events = sorted_records[i:j]

        if len(window_events) >= threshold:
            alerts.append(
                (
                    start_time,
                    end_limit,
                    len(window_events),
                    tuple(r.line_number for r in window_events),
                )
            )
            # Advance past this window so we don't spam duplicate alerts for the same burst
            i = j
        else:
            i += 1

    return alerts


def repeat_404(records, window_seconds=10, threshold=6):
    """Flag a client that returns many 404s inside any 10s window."""
    by_client = defaultdict(list)
    for r in records:
        if r.status == 404:
            by_client[r.client_ip].append(r)

    alerts = []
    for client, recs in by_client.items():
        recs.sort(key=lambda r: r.timestamp)
        for start, end, count, lines in _scan_windows(recs, window_seconds, threshold):
            alerts.append(
                Alert(
                    rule="repeat_404",
                    client_ip=client,
                    start=start,
                    end=end,
                    count=count,
                    threshold=threshold,
                    lines=lines,
                )
            )
    return alerts


def backend_502(records, window_seconds=10, threshold=5):
    """Flag many 502 responses inside any 10s window across any client."""
    errs = [r for r in records if r.status == 502]
    errs.sort(key=lambda r: r.timestamp)

    alerts = []
    for start, end, count, lines in _scan_windows(errs, window_seconds, threshold):
        alerts.append(
            Alert(
                rule="backend_502",
                client_ip=None,
                start=start,
                end=end,
                count=count,
                threshold=threshold,
                lines=lines,
            )
        )
    return alerts


def request_burst(records, window_seconds=10, threshold=10):
    """Flag a client that sends many requests inside any 10s window."""
    by_client = defaultdict(list)
    for r in records:
        by_client[r.client_ip].append(r)

    alerts = []
    for client, recs in by_client.items():
        recs.sort(key=lambda r: r.timestamp)
        for start, end, count, lines in _scan_windows(recs, window_seconds, threshold):
            alerts.append(
                Alert(
                    rule="request_burst",
                    client_ip=client,
                    start=start,
                    end=end,
                    count=count,
                    threshold=threshold,
                    lines=lines,
                )
            )
    return alerts
