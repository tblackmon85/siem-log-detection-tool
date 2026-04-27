import re

# Simple patterns for suspicious activity
SUSPICIOUS_PATTERNS = [
    r"failed login",
    r"invalid user",
    r"unauthorized access",
    r"sql injection",
    r"command not allowed",
    r"access denied"
]

def detect_threats(log_file):
    alerts = []

    with open(log_file, "r") as file:
        for line_number, line in enumerate(file, start=1):
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    alerts.append((line_number, line.strip(), pattern))

    return alerts

def main():
    log_file = "sample_logs.txt"
    alerts = detect_threats(log_file)

    if alerts:
        print("Suspicious Activity Detected:\n")
        for alert in alerts:
            print(f"[Line {alert[0]}] Pattern: '{alert[2]}' → {alert[1]}")
    else:
        print("No suspicious activity found.")

if __name__ == "__main__":
    main()
