#  → Logging & alert persistence

from datetime import datetime
import os

def log_alert(message, log_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    with open(log_file, "a") as f:
        f.write(entry)

    print(entry)
