import csv
import os
from collections import Counter

def generate_report():
    """Reads the blocklist and generates a security summary."""
    blocklist_path = "../blocklist.txt"
    
    # Check if the file exists before trying to read it
    if not os.path.exists(blocklist_path):
        print("[-] No blocklist found. The perimeter is secure.")
        return

    ips = []
    locations = []

    # Open and read the blocklist
    with open(blocklist_path, "r") as f:
        lines = f.read().splitlines()

    for line in lines:
            parts = line.split(",")
            
            # This line handles both simple IPs and enriched data
            ip = parts[0].strip()
            ips.append(ip)
            
            # Only add to locations if the data actually exists
            if len(parts) >= 3:
                location = ",".join(parts[2:]).strip()
                locations.append(location)
            else:
                locations.append("Unknown/Local")

    # Count the occurrences of each IP and Location
    ip_counts = Counter(ips)
    location_counts = Counter(locations)

    # Print the automated report
    print("\n" + "="*40)
    print("🛡️  SECUREVAULT THREAT DIGEST  🛡️")
    print("="*40)
    
    print("\n[+] TOP ATTACKING IPs:")
    for ip, count in ip_counts.most_common(5):
        print(f"    - {ip}: {count} blocks")

    print("\n[+] TOP THREAT ORIGINS (GEO-LOCATION):")
    for loc, count in location_counts.most_common(5):
        print(f"    - {loc}: {count} blocks")
        
    print("\n" + "="*40 + "\n")

 # --- NEW: Export to CSV ---
    csv_file = "Daily_Security_Report.csv"
    
    # We combine the data into a list of rows for the spreadsheet
    report_data = Counter(ips).most_common()

    with open(csv_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        # Write the Header Row
        writer.writerow(["IP Address", "Attack Count"])
        
        # Write the Data Rows
        for ip, count in report_data:
            writer.writerow([ip, count])

if __name__ == "__main__":
    generate_report()
