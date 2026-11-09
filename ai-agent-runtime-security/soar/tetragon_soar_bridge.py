#!/usr/bin/env python3
"""Tetragon-to-Docker SOAR bridge. Quarantine is disabled unless --execute is set."""

import argparse
import json
import subprocess
import sys
import time

POLICY = "ai-agent-workspace-write"
HOOK = "security_file_permission"
PATH_PREFIX = "/workspace/output/"
TARGET_NAME = "ai-agent-soar-test"
TARGET_IMAGE = "ai-agent-sandbox:baseline"
REQUIRED_LABELS = {
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


def extract_candidate(event):
    """Return a Docker ID prefix only for a valid successful write event."""
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
    permission_arg = args[1].get("int_arg")
    return_code = result.get("int_arg")

    if not isinstance(path, str) or not path.startswith(PATH_PREFIX):
        return None

    relative_path = path[len(PATH_PREFIX):]
    components = relative_path.split("/")
    if not relative_path or any(part in ("", ".", "..") for part in components):
        return None

    if type(permission_arg) is not int or permission_arg != 2:
        return None
    if type(return_code) is not int or return_code != 0:
        return None

    container_id = process.get("docker")
    if not isinstance(container_id, str) or len(container_id) < 12:
        return None
    if any(c not in "0123456789abcdef" for c in container_id.lower()):
        return None

    return container_id.lower()


def resolve_approved_target(event_id):
    """Resolve a Tetragon ID prefix and enforce the fixed target identity."""
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

    checks = {
        "exact_id_prefix": full_id.startswith(event_id),
        "exact_name": inspected.get("Name", "").lstrip("/") == TARGET_NAME,
        "expected_image": config.get("Image") == TARGET_IMAGE,
        "running": (inspected.get("State") or {}).get("Status") == "running",
        "approved_role": labels.get("security.lab.role") == "disposable-agent",
        "approved_quarantine": labels.get("security.lab.quarantine") == "true",
        "not_privileged": host.get("Privileged") is False,
        "no_network": host.get("NetworkMode") == "none",
    }

    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError("Target validation failed: " + ", ".join(failed))

    return full_id


def handle_event(event, execute=False):
    received_at = time.monotonic()
    event_id = extract_candidate(event)
    if event_id is None:
        return "IGNORED: event did not meet detection criteria"

    try:
        target_id = resolve_approved_target(event_id)
    except (ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return f"REJECTED: {exc}"

    if not execute:
        return f"DRY-RUN: would quarantine {TARGET_NAME} ({target_id})"

    try:
        docker(["stop", "--time", "2", target_id])
        final_state = docker([
            "inspect", "--format", "{{.State.Status}}", target_id
        ]).stdout.strip()
    except subprocess.SubprocessError as exc:
        return f"QUARANTINE_UNCONFIRMED: Docker operation failed: {exc}"

    reaction_seconds = time.monotonic() - received_at
    if final_state != "exited":
        return (
            f"QUARANTINE_UNCONFIRMED: {TARGET_NAME} ({target_id}); "
            f"reported_state={final_state!r}; "
            f"bridge_reaction_seconds={reaction_seconds:.3f}"
        )

    return (
        f"QUARANTINED: {TARGET_NAME} ({target_id}); "
        f"verified_state=exited; "
        f"bridge_reaction_seconds={reaction_seconds:.3f}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually stop the explicitly approved disposable target",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read JSONL events from stdin instead of connecting to Tetragon",
    )
    options = parser.parse_args()

    if options.stdin:
        stream = sys.stdin
        for line in stream:
            try:
                event = json.loads(line)
                print(handle_event(event, options.execute), flush=True)
            except json.JSONDecodeError as exc:
                print(f"IGNORED: invalid JSON: {exc}", flush=True)
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
        "Connecting to Tetragon event stream...",
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
