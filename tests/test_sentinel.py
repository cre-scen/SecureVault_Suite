"""LogSentinel's parsing and blocklist handling.

The monitor() loop itself tails a file forever, so it isn't covered here.
"""

import pytest
import sentinel

WERKZEUG_401 = (
    '2026-11-02 12:00:00,000 - 203.0.113.9 - - [02/Nov/2026 12:00:00] '
    '"GET /secret/x HTTP/1.1" 401 -'
)
APP_WARNING = "2026-11-02 12:00:00,000 - 401 UNAUTHORIZED: Invalid Key Attempt."


def test_regex_extracts_ip_and_status_from_access_line():
    match = sentinel.ACCESS_LOG_RE.search(WERKZEUG_401)
    assert match is not None
    assert match.group("ip") == "203.0.113.9"
    assert match.group("status") == "401"


def test_regex_ignores_the_apps_own_warning_line():
    # The app also logs a warning for each bad key. Counting it as well would
    # double-count every attempt, so only the access-log line may match.
    assert sentinel.ACCESS_LOG_RE.search(APP_WARNING) is None


def test_regex_reads_non_401_statuses_so_they_can_be_skipped():
    line = WERKZEUG_401.replace('" 401 -', '" 200 -')
    assert sentinel.ACCESS_LOG_RE.search(line).group("status") == "200"


@pytest.mark.xfail(strict=True, reason="Known issue: IPv6 clients are never counted (M3)")
def test_regex_should_match_ipv6_clients():
    line = WERKZEUG_401.replace("203.0.113.9", "2001:db8::9")
    match = sentinel.ACCESS_LOG_RE.search(line)
    assert match is not None and match.group("ip") == "2001:db8::9"


def test_load_blocked_ips_reads_enriched_lines(blocklist_path, monkeypatch):
    monkeypatch.setattr(sentinel, "BLOCKLIST_PATH", str(blocklist_path))
    blocklist_path.write_text("203.0.113.9,2026-11-02 12:00:00,Paris, France\n\n10.0.0.66\n")
    assert sentinel.load_blocked_ips() == {"203.0.113.9", "10.0.0.66"}


def test_block_ip_for_private_address_makes_no_network_call(blocklist_path, monkeypatch):
    monkeypatch.setattr(sentinel, "BLOCKLIST_PATH", str(blocklist_path))
    blocklist_path.unlink(missing_ok=True)

    def no_network(*args, **kwargs):
        raise AssertionError("geolocation lookup must not run for private IPs")

    monkeypatch.setattr(sentinel.urllib.request, "urlopen", no_network)
    sentinel.block_ip("10.0.0.66")
    ip, _timestamp, location = blocklist_path.read_text().strip().split(",", 2)
    assert (ip, location) == ("10.0.0.66", "Local Network")


def test_all_components_share_the_same_files():
    # The detect-and-block loop only works if every side uses the same files.
    import app
    import threat_report

    assert sentinel.BLOCKLIST_PATH == app.BLOCKLIST_PATH == threat_report.BLOCKLIST_PATH
    assert sentinel.LOG_PATH == app.LOG_PATH
