"""LogSentinel must count exactly one 401 per failed request.

This runs the real Werkzeug server (not the Flask test client, which writes no
access-log lines) so the regex is checked against the exact format it parses
in production, plus the app's own "401 UNAUTHORIZED" warning line.
"""

import logging
import os
import threading
import urllib.error
import urllib.request

from werkzeug.serving import make_server

import sentinel


def test_sentinel_uses_overridden_paths(app_module):
    # Coupled paths: sentinel must read what the app writes
    assert sentinel.LOG_PATH == app_module.LOG_PATH
    assert sentinel.BLOCKLIST_PATH == app_module.BLOCKLIST_PATH


def test_regex_counts_one_401_line_per_request(client, app_module):
    log_path = app_module.LOG_PATH
    start = os.path.getsize(log_path) if os.path.exists(log_path) else 0

    server = make_server("127.0.0.1", 0, app_module.app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/secret/anything"
        req = urllib.request.Request(url, headers={"X-API-Key": "wrong-key"})
        try:
            urllib.request.urlopen(req, timeout=5)  # nosec B310: local test server
            raise AssertionError("expected a 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        server.shutdown()
        thread.join(timeout=5)

    for h in logging.getLogger().handlers:
        h.flush()
    with open(log_path, encoding="utf-8") as f:
        f.seek(start)
        new_lines = f.read().splitlines()

    # Sanity: both the app's warning and Werkzeug's access line were written
    assert any("401 UNAUTHORIZED" in line for line in new_lines), new_lines
    hits = [
        m for m in (sentinel.ACCESS_LOG_RE.search(line) for line in new_lines)
        if m and m.group("status") == "401"
    ]
    assert len(hits) == 1, new_lines
    assert hits[0].group("ip") == "127.0.0.1"
