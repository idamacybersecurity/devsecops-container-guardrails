import json
import os
import time
import urllib.request
from urllib.parse import urlparse

API_URL = os.getenv("API_URL", "http://api-service:5000/health")


def validate_api_url(url):
    parsed_url = urlparse(url)

    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError(
            "API_URL must use the http or https scheme"
        )

    return url


def check_api():
    try:
        safe_api_url = validate_api_url(API_URL)

        # B310 reviewed: URL scheme is restricted to HTTP/HTTPS above.
        with urllib.request.urlopen(  # nosec B310
            safe_api_url,
            timeout=5
        ) as response:
            data = json.loads(response.read().decode())
            print(f"API health check: {data}", flush=True)
    except Exception as error:
        print(f"API health check failed: {error}", flush=True)


if __name__ == "__main__":
    while True:
        check_api()
        time.sleep(30)
