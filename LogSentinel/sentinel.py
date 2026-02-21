import time
import os
import urllib.request
import json
from datetime import datetime

def get_location(ip):
    """Fetches the physical location of an IP address."""
    # Localhost (your own computer) doesn't have a real physical map location
    if ip == "127.0.0.1":
        return "Localhost (Your Machine)"
    
    try:
        # We use a free public API to lookup the IP
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urllib.request.urlopen(req)
        data = json.loads(response.read().decode('utf-8'))
        
        city = data.get("city", "Unknown City")
        country = data.get("country_name", "Unknown Country")
        return f"{city}, {country}"
    except Exception as e:
        return "Location unavailable"

def block_ip(ip_address):
    """Adds a malicious IP, Time, and Location to the blocklist."""
    blocklist_path = "../blocklist.txt"
    
    # Get the exact current time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get the location of the attacker
    location = get_location(ip_address)
    
    # Write to file (Format: IP, Time, Location)
    with open(blocklist_path, "a") as f:
        f.write(f"{ip_address},{current_time},{location}\n")
        
    print(f"\n[#] ACTION TAKEN: {ip_address} BLOCKED!")
    print(f"[#] TIME: {current_time}")
    print(f"[#] LOCATION: {location}\n")

# CONFIGURATION
LOG_PATH = "../SecureVaultAPI/app.log"
THRESHOLD = 5
WINDOW_SECONDS = 60

def monitor():
    failed_login_count = 0
    first_fail_time = None

    print(f"[*] LogSentinel Active. Monitoring: {LOG_PATH}")
    print("[*] Waiting for threshold (5 hits) to trigger alert...")

    # Wait for file to exist
    while not os.path.exists(LOG_PATH):
        time.sleep(1)

    with open(LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            if "401" in line:
                current_time = time.time()
                
                # Window logic: Reset if 60s has passed since the first fail
                if first_fail_time is None or (current_time - first_fail_time > WINDOW_SECONDS):
                    first_fail_time = current_time
                    failed_login_count = 1
                else:
                    failed_login_count += 1

                print(f"[!] Hit detected. Count: {failed_login_count}/{THRESHOLD}")

                if failed_login_count >= THRESHOLD:
                    print("\n" + "!" * 40)
                    print("!!! SECURITY ALERT: BRUTE FORCE DETECTED !!!")
                    print("!" * 40 + "\n")
                    block_ip("127.0.0.1")  # In a real scenario, extract the actual IP from the log
                    # Reset after alert
                    failed_login_count = 0 
                    first_fail_time = None

if __name__ == "__main__":
    monitor()