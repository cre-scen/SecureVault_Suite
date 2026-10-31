import csv
import os
from collections import Counter

# Paths are resolved relative to this file, matching sentinel.py and app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUITE_DIR = os.path.dirname(BASE_DIR)
BLOCKLIST_PATH = os.path.join(SUITE_DIR, "blocklist.txt")
REPORT_PATH = os.path.join(BASE_DIR, "Daily_Security_Report.csv")


def generate_report():
    """Reads the blocklist and generates a security summary."""
    # Check if the file exists before trying to read it
    if not os.path.exists(BLOCKLIST_PATH):
        print("[-] No blocklist found. The perimeter is secure.")
        return

    ips = []
    locations = []

    # Open and read the blocklist, skipping blank lines
    with open(BLOCKLIST_PATH, "r") as f:
        lines = [line for line in f.read().splitlines() if line.strip()]

    for line in lines:
        parts = line.split(",")

        # Handles both simple IPs and enriched (IP,time,location) entries
        ip = parts[0].strip()
        ips.append(ip)

        if len(parts) >= 3:
            location = ",".join(parts[2:]).strip()
            locations.append(location)
        else:
            locations.append("Unknown/Local")

    ip_counts = Counter(ips)
    location_counts = Counter(locations)

    # Print the automated report (ASCII only, so it works on any console)
    print("\n" + "=" * 40)
    print("   SECUREVAULT THREAT DIGEST")
    print("=" * 40)

    print("\n[+] TOP ATTACKING IPs:")
    for ip, count in ip_counts.most_common(5):
        print(f"    - {ip}: {count} blocks")

    print("\n[+] TOP THREAT ORIGINS (GEO-LOCATION):")
    for loc, count in location_counts.most_common(5):
        print(f"    - {loc}: {count} blocks")

    print("\n" + "=" * 40 + "\n")

    # Export to CSV
    with open(REPORT_PATH, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Attack Count"])
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

    print(f"[+] Report saved to {REPORT_PATH}")


if __name__ == "__main__":
    generate_report()
