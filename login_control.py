import time
from datetime import datetime, timedelta
import json

# Step 1: Track failed attempts in memory
failed_attempts = {} # username: {count, last_attempt, lockout_until}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 15 * 60 # 15 minutes in seconds
AUDIT_LOG_FILE = "security_audit.log"

# Dummy user database
USERS = {"admin": "password123", "deepika": "Deepika@2024"}

def log_event(username, ip, event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"[{timestamp}] User:{username} IP:{ip} - {event}\n"
    print(log.strip())
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(log)

def is_locked(username):
    if username in failed_attempts:
        lockout_until = failed_attempts[username].get("lockout_until")
        if lockout_until and datetime.now() < lockout_until:
            remaining = (lockout_until - datetime.now()).seconds
            return True, remaining
    return False, 0

def login(username, password, ip="127.0.0.1"):
    locked, remaining = is_locked(username)
    if locked:
        print(f"[!] Account {username} is LOCKED. Try after {remaining} sec")
        return False

    # Check credentials
    if USERS.get(username) == password:
        # Success - reset counter
        print(f"[+] Login SUCCESS for {username}")
        if username in failed_attempts:
            del failed_attempts[username]
        log_event(username, ip, "Successful login")
        return True
    else:
        # Step 1: Increment failed counter
        if username not in failed_attempts:
            failed_attempts[username] = {"count": 0, "last_attempt": datetime.now()}

        failed_attempts[username]["count"] += 1
        failed_attempts[username]["last_attempt"] = datetime.now()
        count = failed_attempts[username]["count"]

        print(f"[-] Login FAILED for {username}. Attempt {count}/{LOCKOUT_THRESHOLD}")

        # Step 2: Enforce lockout after 5 failures
        if count >= LOCKOUT_THRESHOLD:
            lockout_until = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
            failed_attempts[username]["lockout_until"] = lockout_until
            # Step 3: Log lockout event
            log_event(username, ip, f"ACCOUNT LOCKED after {count} failed attempts. Locked for 15 min")
            print(f"[!] ACCOUNT LOCKED for 15 minutes due to brute-force!")
        else:
            # Progressive delay
            delay = 2 ** (count-1)
            print(f"[*] Enforcing progressive delay: {delay} sec")
            time.sleep(1) # For demo we sleep 1 sec only

        log_event(username, ip, f"Failed login attempt {count}")
        return False

# Step 4: Test against simulated brute-force
if __name__ == "__main__":
    print("=== Login Attempt Control System ===")
    print("Testing brute-force protection\n")

    test_user = "admin"
    fake_ip = "192.168.1.10"

    # Simulate 6 wrong attempts
    for i in range(6):
        print(f"\n--- Attempt {i+1} ---")
        login(test_user, "wrong_password", fake_ip)

    print("\n--- Trying correct password while locked ---")
    login(test_user, "password123", fake_ip)

    print("\n--- Audit Log ---")
    try:
        with open(AUDIT_LOG_FILE, 'r') as f:
            print(f.read())
    except:
        print("No log yet")
