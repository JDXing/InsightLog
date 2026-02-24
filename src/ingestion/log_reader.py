import time
import os

LOG_FILE = "/var/log/auth.log"

def follow():
    """
    Generator function that continuously monitors the auth log
    and yields new lines in real time.
    """

    if not os.path.exists(LOG_FILE):
        raise FileNotFoundError(f"{LOG_FILE} not found.")

    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)  # Move pointer to end of file

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line.strip()