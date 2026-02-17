import time
import os

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
                    # Reset after alert
                    failed_login_count = 0 
                    first_fail_time = None

if __name__ == "__main__":
    monitor()