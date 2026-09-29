import json
import os
import time
import urllib.request

API_URL = os.getenv("API_URL", "http://api-service:5000/health")


def check_api():
    try:
        with urllib.request.urlopen(API_URL, timeout=5) as response:
            data = json.loads(response.read().decode())
            print(f"API health check: {data}", flush=True)
    except Exception as error:
        print(f"API health check failed: {error}", flush=True)


if __name__ == "__main__":
    while True:
        check_api()
        time.sleep(30)
