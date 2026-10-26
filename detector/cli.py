"""Command-line entry point: summarize a log file and run detection rules.

Usage:
    python3 -m detector.cli <path-to-access-log>
"""

import sys

from detector.nginx_parser import parse_file
from detector.summarize import build_summary
from detector import rules


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 -m detector.cli <path-to-access-log>")
        return 2

    path = argv[1]

    try:
        records, rejected = parse_file(path)
    except OSError as exc:
        print(f"Error: cannot read file: {exc}")
        return 1

    summary = build_summary(records, rejected)

    print(f"File:      {path}")
    print(f"Parsed:    {summary.total_requests}")
    print(f"Rejected:  {summary.rejected_lines}")

    first = summary.first_request_time
    last = summary.last_request_time
    if first is None or last is None:
        print("No valid records in file.")
        return 0

    print(f"Span:      {first:%Y-%m-%d %H:%M:%S %Z} -> {last:%Y-%m-%d %H:%M:%S %Z}")

    print("\nStatus codes:")
    for status, count in sorted(summary.status_counts.items()):
        print(f"  {status}: {count}")

    print("\nTop clients:")
    for client, count in sorted(summary.client_counts.items()):
        print(f"  {client}: {count}")

    alert_fns = [
        ("repeat_404", rules.repeat_404, dict(window_seconds=10, threshold=6)),
        ("backend_502", rules.backend_502, dict(window_seconds=10, threshold=5)),
        ("request_burst", rules.request_burst, dict(window_seconds=10, threshold=10)),
    ]

    print("\nDetections:")
    any_alert = False
    for name, fn, kwargs in alert_fns:
        found = fn(records, **kwargs)
        if not found:
            print(f"  -- {name}: none")
            continue
        any_alert = True
        for a in found:
            start = a.start.strftime("%Y-%m-%d %H:%M:%S")
            client = a.client_ip or "any-client"
            lines = ",".join(str(x) for x in a.lines)
            print(f"  [ALERT] {name}: {client} @ {start} "
                  f"({a.count} >= {a.threshold}) lines {lines}")

    if not any_alert:
        print("  No detections.")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
