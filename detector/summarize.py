"""Turn parsed log records into summary statistics."""

from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Summary:
    total_requests: int
    status_counts: dict
    client_counts: dict
    first_request_time: object
    last_request_time: object
    rejected_lines: int


def build_summary(records, rejected):
    if records:
        first_time = min(r.timestamp for r in records)
        last_time = max(r.timestamp for r in records)
    else:
        first_time = None
        last_time = None

    return Summary(
        total_requests=len(records),
        status_counts=dict(Counter(r.status for r in records)),
        client_counts=dict(Counter(r.client_ip for r in records)),
        first_request_time=first_time,
        last_request_time=last_time,
        rejected_lines=len(rejected),
    )
