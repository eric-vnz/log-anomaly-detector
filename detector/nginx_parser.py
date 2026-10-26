"""Parse Nginx combined-style access-log lines into structured records."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

LINE_PATTERN = re.compile(
    r'(?P<client_ip>\S+) '
    r'(?P<remote_identity>\S+) '
    r'(?P<remote_user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<body_bytes_sent>\d+|-) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

TIMESTAMP_PATTERN = re.compile(
    r'(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) '
    r'(?P<sign>[+-])(?P<off_h>\d{2})(?P<off_m>\d{2})'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class ParseError(ValueError):
    """Raised when a line cannot be turned into a valid record."""


@dataclass(frozen=True)
class LogRecord:
    line_number: int
    client_ip: str
    timestamp: datetime
    method: str
    request_target: str
    protocol: str
    status: int
    body_bytes_sent: int | None
    referrer: str | None
    user_agent: str | None


def parse_timestamp(text: str) -> datetime:
    match = TIMESTAMP_PATTERN.fullmatch(text)
    if match is None:
        raise ParseError(f"unrecognised timestamp format: {text!r}")

    month = MONTHS.get(match["month"])
    if month is None:
        raise ParseError(f"unknown month name: {match['month']!r}")

    off_h = int(match["off_h"])
    off_m = int(match["off_m"])
    if off_h > 23 or off_m > 59:
        raise ParseError(f"invalid timezone offset: {text!r}")

    offset = timedelta(hours=off_h, minutes=off_m)
    if match["sign"] == "-":
        offset = -offset

    try:
        return datetime(
            int(match["year"]), month, int(match["day"]),
            int(match["hour"]), int(match["minute"]), int(match["second"]),
            tzinfo=timezone(offset),
        )
    except ValueError as exc:
        raise ParseError(f"invalid date or time: {exc}") from exc


def parse_line(line: str, line_number: int) -> LogRecord:
    match = LINE_PATTERN.fullmatch(line)
    if match is None:
        raise ParseError("line does not match the expected log structure")

    request_parts = match["request"].split()
    if len(request_parts) != 3:
        raise ParseError(
            f"request is not 'METHOD TARGET PROTOCOL': {match['request']!r}"
        )
    method, request_target, protocol = request_parts

    sent = match["body_bytes_sent"]
    referrer = match["referrer"]
    user_agent = match["user_agent"]

    return LogRecord(
        line_number=line_number,
        client_ip=match["client_ip"],
        timestamp=parse_timestamp(match["timestamp"]),
        method=method,
        request_target=request_target,
        protocol=protocol,
        status=int(match["status"]),
        body_bytes_sent=None if sent == "-" else int(sent),
        referrer=None if referrer == "-" else referrer,
        user_agent=None if user_agent == "-" else user_agent,
    )


def parse_file(path: str):
    """Return (records, rejected). Every input line lands in exactly one list."""
    records = []
    rejected = []  # tuples of (line_number, reason, raw_line)

    with open(path, encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\r\n")
            try:
                records.append(parse_line(line, line_number))
            except ParseError as exc:
                rejected.append((line_number, str(exc), line))

    return records, rejected
