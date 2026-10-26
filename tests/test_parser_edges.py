from pathlib import Path
import tempfile

from detector.nginx_parser import (
    LogRecord, ParseError, parse_file, parse_line,
)

# A known GOOD line, so each test can start from something we trust.
VALID_LINE = (
    '127.0.0.1 - - [04/Oct/2026:19:50:26 +0000] '
    '"GET /api/v1/health HTTP/1.1" 502 150 "-" "curl/7.81.0"'
)

passed = 0
failed = 0


def run(name, fn):
    global passed, failed
    try:
        fn()
    except AssertionError as exc:
        failed += 1
        print(f"[FAIL] {name}: {exc}")
    except Exception as exc:
        failed += 1
        print(f"[FAIL] {name}: unexpected {type(exc).__name__}: {exc}")
    else:
        passed += 1
        print(f"[PASS] {name}")


# 1. A normal line should become a correct record.
def test_valid_line():
    rec = parse_line(VALID_LINE, 19)
    assert isinstance(rec, LogRecord)
    assert rec.client_ip == "127.0.0.1"
    assert rec.request_target == "/api/v1/health"
    assert rec.status == 502
    assert rec.body_bytes_sent == 150
    assert rec.referrer is None
    assert rec.user_agent == "curl/7.81.0"


# 2. A date that doesn't exist must be rejected, not guessed.
def test_impossible_date():
    line = VALID_LINE.replace("04/Oct/2026", "31/Feb/2026")
    try:
        parse_line(line, 1)
    except ParseError:
        return
    raise AssertionError("expected ParseError for 31 February")


# 3. A timezone offset with 60 minutes must be rejected, not normalised.
def test_invalid_tz_minutes():
    line = VALID_LINE.replace("+0000", "+0060")
    try:
        parse_line(line, 1)
    except ParseError:
        return
    raise AssertionError("expected ParseError for +0060")


# 4. A request that is missing its protocol must be rejected.
def test_incomplete_request():
    line = (
        '127.0.0.1 - - [04/Oct/2026:19:50:26 +0000] '
        '"GET /path" 502 150 "-" "-"'
    )
    try:
        parse_line(line, 1)
    except ParseError:
        return
    raise AssertionError("expected ParseError for missing protocol")


# 5. A bad line must NOT stop the file from being parsed.
def test_continue_after_reject():
    content = (
        '127.0.0.1 - - [04/Oct/2026:19:50:26 +0000] "GET /ok HTTP/1.1" 200 10 "-" "-"\n'
        'this is not a log line\n'
        '127.0.0.1 - - [04/Oct/2026:19:50:27 +0000] "GET /ok2 HTTP/1.1" 200 10 "-" "-"\n'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        name = fh.name
        fh.write(content)
    try:
        records, rejected = parse_file(name)
        assert len(records) == 2
        assert len(rejected) == 1
        assert rejected[0][0] == 2    # the bad line was line 2
        assert records[0].line_number == 1
        assert records[1].line_number == 3
    finally:
        Path(name).unlink()


# 6. An empty file must return empty results, not crash.
def test_empty_file():
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        name = fh.name
    try:
        records, rejected = parse_file(name)
        assert records == []
        assert rejected == []
    finally:
        Path(name).unlink()


run("valid line parses", test_valid_line)
run("impossible date rejected", test_impossible_date)
run("invalid tz minutes rejected", test_invalid_tz_minutes)
run("incomplete request rejected", test_incomplete_request)
run("continue after rejected line", test_continue_after_reject)
run("empty file", test_empty_file)

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
