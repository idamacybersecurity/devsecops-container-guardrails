"""Per-operation Boto3 timing for CCPD responder diagnostics."""
import datetime
import functools
import json
import os
import threading
import time
from pathlib import Path

_write_lock = threading.Lock()
_original_session_client = None


def _write_record(record):
    path = Path(os.environ.get(
        "CCPD_BOTO3_TIMING_LOG",
        "evidence/runtime/boto3-call-timings.jsonl",
    ))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(record, sort_keys=True) + "\n").encode()
        with _write_lock:
            fd = os.open(
                str(path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
    except OSError:
        # Diagnostics must never break or alter a security response.
        pass


def instrument_boto3_client(client):
    """Wrap every modeled API operation on one Boto3 client."""
    if getattr(client, "_ccpd_timing_instrumented", False):
        return client

    service = client.meta.service_model.service_name

    for method_name, operation_name in client.meta.method_to_api_mapping.items():
        original_method = getattr(client, method_name)

        @functools.wraps(original_method)
        def timed_method(
            *args,
            __original=original_method,
            __operation=operation_name,
            **kwargs,
        ):
            started = time.perf_counter()
            timestamp = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

            try:
                result = __original(*args, **kwargs)
            except Exception as exc:
                elapsed = time.perf_counter() - started
                response = getattr(exc, "response", {}) or {}
                error = response.get("Error", {}) or {}
                metadata = response.get("ResponseMetadata", {}) or {}

                _write_record({
                    "timestamp_utc": timestamp,
                    "service": service,
                    "operation": __operation,
                    "duration_seconds": round(elapsed, 6),
                    "status": "error",
                    "error_code": error.get("Code"),
                    "error_type": type(exc).__name__,
                    "request_id": metadata.get("RequestId"),
                    "retry_attempts": metadata.get("RetryAttempts"),
                })
                raise

            elapsed = time.perf_counter() - started
            metadata = result.get("ResponseMetadata", {}) or {}

            _write_record({
                "timestamp_utc": timestamp,
                "service": service,
                "operation": __operation,
                "duration_seconds": round(elapsed, 6),
                "status": "success",
                "error_code": None,
                "error_type": None,
                "request_id": metadata.get("RequestId"),
                "retry_attempts": metadata.get("RetryAttempts"),
            })
            return result

        setattr(client, method_name, timed_method)

    client._ccpd_timing_instrumented = True
    return client


def install_boto3_call_timing():
    """Instrument clients created after this function is installed."""
    global _original_session_client

    import boto3.session

    session_class = boto3.session.Session
    current = session_class.client

    if getattr(current, "_ccpd_timing_installed", False):
        return

    _original_session_client = current

    @functools.wraps(current)
    def timed_session_client(self, *args, **kwargs):
        client = current(self, *args, **kwargs)
        return instrument_boto3_client(client)

    timed_session_client._ccpd_timing_installed = True
    session_class.client = timed_session_client
