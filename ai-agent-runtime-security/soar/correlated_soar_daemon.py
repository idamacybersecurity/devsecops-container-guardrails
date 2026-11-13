#!/usr/bin/env python3
"""Correlate Tetragon write events to a strictly validated Docker AI agent."""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone

POLICY = "ai-agent-workspace-write"
HOOK = "security_file_permission"
PATH_PREFIX = "/workspace/output/"
TARGET_NAME = "ai-agent-correlated-soar"
TARGET_IMAGE = "ai-agent-sandbox:baseline"

REQUIRED_LABELS = {
    "role": "ai-agent",
    "security.lab.role": "disposable-agent",
    "security.lab.quarantine": "true",
}


def docker(args):
    return subprocess.run(
        ["docker", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def parse_event_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).timestamp()
    except ValueError:
        return None


def extract_candidate(event):
    """Return (container ID prefix, event epoch, path) for a valid event."""
    if not isinstance(event, dict):
        return None

    data = event.get("process_kprobe")
    if not isinstance(data, dict):
        return None

    process = data.get("process")
    args = data.get("args")
    result = data.get("return")

    if not isinstance(process, dict):
        return None
    if not isinstance(args, list) or len(args) < 2:
        return None
    if not isinstance(args[0], dict) or not isinstance(args[1], dict):
        return None
    if not isinstance(result, dict):
        return None

    if data.get("policy_name") != POLICY:
        return None
    if data.get("function_name") != HOOK:
        return None
    if data.get("action") != "KPROBE_ACTION_POST":
        return None

    file_arg = args[0].get("file_arg")
    if not isinstance(file_arg, dict):
        return None

    path = file_arg.get("path")
    permission = args[1].get("int_arg")
    return_code = result.get("int_arg")

    if not isinstance(path, str) or not path.startswith(PATH_PREFIX):
        return None

    relative = path[len(PATH_PREFIX):]
    parts = relative.split("/")
    if not relative or any(part in ("", ".", "..") for part in parts):
        return None

    if type(permission) is not int or permission != 2:
        return None
    if type(return_code) is not int or return_code != 0:
        return None

    container_id = process.get("docker")
    if not isinstance(container_id, str):
        return None
    if len(container_id) < 12 or len(container_id) > 64:
        return None
    if any(c not in "0123456789abcdef" for c in container_id.lower()):
        return None

    event_epoch = parse_event_time(event.get("time"))
    if event_epoch is None:
        return None

    return container_id.lower(), event_epoch, path


def resolve_approved_target(event_id):
    """Resolve one unique Docker ID prefix and validate the disposable target."""
    inventory = docker(["ps", "-aq", "--no-trunc"]).stdout.splitlines()
    matches = [
        item.strip().lower()
        for item in inventory
        if item.strip().lower().startswith(event_id)
    ]

    if len(matches) != 1:
        raise ValueError(f"Expected one Docker ID match; found {len(matches)}")

    full_id = matches[0]
    inspected = json.loads(docker(["inspect", full_id]).stdout)[0]
    config = inspected.get("Config") or {}
    host = inspected.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    state = inspected.get("State") or {}

    checks = {
        "exact_id_prefix": full_id.startswith(event_id),
        "exact_name": inspected.get("Name", "").lstrip("/") == TARGET_NAME,
        "expected_image": config.get("Image") == TARGET_IMAGE,
        "running": state.get("Status") == "running",
        "required_labels": all(
            labels.get(key) == value
            for key, value in REQUIRED_LABELS.items()
        ),
        "not_privileged": host.get("Privileged") is False,
        "network_disabled": host.get("NetworkMode") == "none",
        "read_only_rootfs": host.get("ReadonlyRootfs") is True,
        "all_capabilities_dropped": "ALL" in (host.get("CapDrop") or []),
    }

    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError("Target validation failed: " + ", ".join(failed))

    return full_id


def handle_event(event, execute=False):
    candidate = extract_candidate(event)
    if candidate is None:
        return "IGNORED: event did not meet detection criteria"

    event_id, event_epoch, path = candidate

    try:
        target_id = resolve_approved_target(event_id)
    except (
        ValueError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        return f"REJECTED: {exc}"

    if not execute:
        return (
            f"DRY-RUN: candidate={TARGET_NAME} container_id={target_id} "
            f"event_time={event.get('time')} path={path}"
        )

    try:
        docker(["kill", "--signal", "KILL", target_id])

        deadline = time.monotonic() + 5.0
        while True:
            inspected = json.loads(
                docker(["inspect", target_id]).stdout
            )[0]
            state = inspected.get("State") or {}
            status = state.get("Status")

            if status == "exited":
                break

            if time.monotonic() >= deadline:
                return (
                    f"QUARANTINE_UNCONFIRMED: container_id={target_id} "
                    f"state={status!r}; exit was not verified within 5 seconds"
                )

            time.sleep(0.1)

    except (
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        return f"QUARANTINE_UNCONFIRMED: Docker operation failed: {exc}"

    exit_code = state.get("ExitCode")
    verified_epoch = time.time()
    verification_latency = verified_epoch - event_epoch

    if status != "exited" or exit_code != 137:
        return (
            f"QUARANTINE_UNCONFIRMED: container_id={target_id} "
            f"state={status!r} exit_code={exit_code!r}"
        )

    if verification_latency < 0:
        return (
            f"QUARANTINED_BUT_CLOCK_INVALID: container_id={target_id} "
            f"verified_exit_code=137 "
            f"negative_event_to_verification_latency={verification_latency:.6f}s"
        )

    finished_at = state.get("FinishedAt")
    finished_epoch = parse_event_time(finished_at)

    if not isinstance(finished_at, str) or not finished_at:
        termination_status = "missing_finished_at"
        termination_latency = "UNAVAILABLE"
    elif finished_epoch is None:
        termination_status = "malformed_finished_at"
        termination_latency = "UNAVAILABLE"
    elif finished_epoch < event_epoch:
        termination_status = "finished_at_precedes_event"
        termination_latency = "INVALID"
    else:
        termination_status = "valid"
        termination_latency = f"{finished_epoch - event_epoch:.6f}"

    return (
        f"QUARANTINED: container_id={target_id} "
        f"verified_state=exited verified_exit_code=137 "
        f"event_time={event.get('time')} "
        f"event_to_termination_seconds={termination_latency} "
        f"termination_timing_status={termination_status} "
        f"event_to_verified_exit_seconds={verification_latency:.6f}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Send SIGKILL to the strictly validated disposable container",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSONL events from stdin",
    )
    options = parser.parse_args()

    if options.stdin:
        for line in sys.stdin:
            try:
                print(
                    handle_event(json.loads(line), options.execute),
                    flush=True,
                )
            except json.JSONDecodeError:
                print("IGNORED: invalid JSON", flush=True)
        return

    command = [
        "docker", "exec", "tetragon",
        "tetra", "getevents",
        "--policy-names", POLICY,
        "--output", "json",
        "--reconnect",
    ]

    print(
        "MODE=" + ("EXECUTE" if options.execute else "DRY-RUN"),
        "Connecting to Tetragon...",
        flush=True,
    )

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        for line in process.stdout:
            try:
                event = json.loads(line)
                print(handle_event(event, options.execute), flush=True)
            except json.JSONDecodeError:
                print("IGNORED: non-JSON stream line", flush=True)
    except KeyboardInterrupt:
        print("Stopping event consumer...", flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
