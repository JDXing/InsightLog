import time

LOG_FILE = "/var/log/auth.log"

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def read_logs():
    try:
        with open(LOG_FILE, "r") as f:
            for line in follow(f):
                print(line.strip())
    except PermissionError:
        print("[!] Permission denied. Run VS Code with sudo.")

if __name__ == "__main__":
    read_logs()
