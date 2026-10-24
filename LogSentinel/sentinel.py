import time
import os
import re
import ipaddress
import urllib.request
import json
from collections import defaultdict, deque
from datetime import datetime

# CONFIGURATION
# Paths are resolved relative to this file, so the script works from any directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUITE_DIR = os.path.dirname(BASE_DIR)
LOG_PATH = os.path.join(SUITE_DIR, "SecureVaultAPI", "app.log")
BLOCKLIST_PATH = os.path.join(SUITE_DIR, "blocklist.txt")  # Same file app.py reads
THRESHOLD = 5
WINDOW_SECONDS = 60

# Matches Werkzeug access-log lines, e.g.
#   ... - 127.0.0.1 - - [21/Feb/2026 11:36:43] "GET /secret/x HTTP/1.1" 401 -
# Only these lines carry the client IP and the status code, and there is exactly
# one per request (the app's own "401 UNAUTHORIZED" warning line is ignored so
# each failed attempt is counted once).
ACCESS_LOG_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[[^\]]*\] ".*" (?P<status>\d{3}) ')


def get_location(ip):
    """Fetches the physical location of an IP address."""
    # Private/loopback addresses don't have a real physical map location
    try:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            return "Local Network"
    except ValueError:
        return "Invalid IP"

    try:
        # We use a free public API to lookup the IP
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))

        city = data.get("city") or "Unknown City"
        country = data.get("country_name") or "Unknown Country"
        return f"{city}, {country}"
    except Exception:
        return "Location unavailable"


def load_blocked_ips():
    """Returns the set of IPs already in the blocklist."""
    if not os.path.exists(BLOCKLIST_PATH):
        return set()
    with open(BLOCKLIST_PATH, "r") as f:
        return {line.split(",")[0].strip() for line in f if line.strip()}


def block_ip(ip_address):
    """Adds a malicious IP, Time, and Location to the blocklist."""
    # Get the exact current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get the location of the attacker
    location = get_location(ip_address)

    # Write to file (Format: IP, Time, Location)
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(f"{ip_address},{current_time},{location}\n")

    print(f"\n[#] ACTION TAKEN: {ip_address} BLOCKED!")
    print(f"[#] TIME: {current_time}")
    print(f"[#] LOCATION: {location}\n")


def monitor():
    # Sliding window of failure timestamps, tracked separately for each IP
    failures = defaultdict(deque)
    blocked_ips = load_blocked_ips()

    print(f"[*] LogSentinel Active. Monitoring: {LOG_PATH}")
    print(f"[*] Waiting for threshold ({THRESHOLD} hits in {WINDOW_SECONDS}s per IP) to trigger alert...")

    # Wait for file to exist
    while not os.path.exists(LOG_PATH):
        time.sleep(1)

    f = open(LOG_PATH, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)

    try:
        while True:
            line = f.readline()
            if not line:
                # Reopen if the log was rotated or truncated
                try:
                    if os.path.getsize(LOG_PATH) < f.tell():
                        f.close()
                        f = open(LOG_PATH, "r", encoding="utf-8", errors="replace")
                except FileNotFoundError:
                    pass
                time.sleep(0.5)
                continue

            match = ACCESS_LOG_RE.search(line)
            if not match or match.group("status") != "401":
                continue

            ip = match.group("ip")
            if ip in blocked_ips:
                continue

            current_time = time.time()
            window = failures[ip]
            window.append(current_time)

            # Drop failures that fell outside the time window
            while window and current_time - window[0] > WINDOW_SECONDS:
                window.popleft()

            print(f"[!] Hit detected from {ip}. Count: {len(window)}/{THRESHOLD}")

            if len(window) >= THRESHOLD:
                print("\n" + "!" * 40)
                print("!!! SECURITY ALERT: BRUTE FORCE DETECTED !!!")
                print("!" * 40 + "\n")
                block_ip(ip)
                blocked_ips.add(ip)
                del failures[ip]
    finally:
        f.close()


if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[*] LogSentinel stopped.")
