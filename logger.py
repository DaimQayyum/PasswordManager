import datetime

LOG_FILE = "app.log"

def log_info(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[INFO] {datetime.datetime.now().isoformat()} - {message}\n")

def log_error(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f"[ERROR] {datetime.datetime.now().isoformat()} - {message}\n") 