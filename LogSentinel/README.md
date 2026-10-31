# LogSentinel

A real-time log monitor that detects brute-force attempts against the SecureVault API and blocks the offending IP. Part of [SecureVault Suite](../README.md).

## How it works

- **Tails `app.log`** from the end of the file, so a restart doesn't re-alert on old entries. It reopens the file automatically after log rotation.
- **Parses Werkzeug access-log lines** with a regex to extract the client IP and HTTP status. Each request is counted exactly once.
- **Tracks failures per IP** in a sliding window (`deque` of timestamps): **5 x `401` within 60 seconds** triggers an alert. This separates a person mistyping a key from automated attacks.
- **Blocks and enriches:** appends `IP,timestamp,location` to `blocklist.txt`. Geolocation comes from ipapi.co with a 5-second timeout and is skipped for private and loopback addresses.
- **Reports:** `threat_report.py` summarises the top attacking IPs and origins and exports `Daily_Security_Report.csv`.

## Usage

```bash
python sentinel.py        # start monitoring
python threat_report.py   # generate the digest and CSV
```

Configuration constants (`THRESHOLD`, `WINDOW_SECONDS`) are at the top of `sentinel.py`.

A standalone version for monitoring other logs is available at [cre-scen/logsentinel](https://github.com/cre-scen/logsentinel).
