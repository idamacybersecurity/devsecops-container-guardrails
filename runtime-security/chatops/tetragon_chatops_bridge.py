#!/usr/bin/env python3
"""
Tetragon gRPC-to-Slack ChatOps bridge.

Consumes Tetragon JSON events through the official tetra gRPC client.
Alerts on:
  - bash/sh process execution
  - namespace-escape policy detections
  - sensitive-file-write policy detections
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import PurePosixPath

LOG = logging.getLogger("tetragon-chatops")

K3S = "/usr/local/bin/k3s"
SOCKET = "unix:///var/run/tetragon/tetragon.sock"

SHELLS = {"bash", "sh"}

SEVERITY = {
    "shell-execution": "MEDIUM",
    "namespace-escape": "HIGH",
    "sensitive-file-write": "HIGH",
}


def get_alert_type(event):
    """Return the alert category for supported Tetragon events."""

    body = event.get("process_exec")
    if body:
        process = body.get("process", {})
        binary = process.get("binary", "")
        pod = process.get("pod") or {}
        pod_name = pod.get("name")
        pod_namespace = pod.get("namespace")

        if (
            PurePosixPath(binary).name in SHELLS
            and pod_name
            and pod_namespace
        ):
            return "shell-execution", body

    body = event.get("process_tracepoint")
    if body and body.get("policy_name") == "namespace-escape":
        return "namespace-escape", body

    body = event.get("process_kprobe")
    if body and body.get("policy_name") == "sensitive-file-write":
        return "sensitive-file-write", body

    return None, None


def get_policy_detail(alert_type, body):
    args = body.get("args", [])

    if alert_type == "namespace-escape":
        for arg in args:
            path = arg.get("linux_binprm_arg", {}).get("path")
            if path:
                return f"Executed path: {path}"
        return body.get("message", "Namespace escape policy matched")

    if alert_type == "sensitive-file-write":
        path = next(
            (a.get("string_arg") for a in args
             if a.get("label") == "file_path"),
            "unknown"
        )
        flags = next(
            (a.get("size_arg") for a in args
             if a.get("label") == "open_flags"),
            "unknown"
        )
        return f"Target: {path}\nOpen flags: {flags}\nHook: {body.get('function_name', 'unknown')}"

    return "Shell process execution detected"


def build_alert(event, alert_type, body):
    process = body.get("process", {})
    parent = body.get("parent", {})
    credentials = process.get("process_credentials", {})

    pod = process.get("pod", {})
    container = pod.get("container", {})
    image = container.get("image", {})

    binary = process.get("binary", "unknown")
    arguments = process.get("arguments", "")
    command = f"{binary} {arguments}".strip()

    image_id = image.get("id", "unknown")
    digest = image_id.rsplit("@", 1)[-1] if "@" in image_id else "not supplied"

    if alert_type == "namespace-escape":
        hook = f"{body.get('subsys', 'unknown')}/{body.get('event', 'unknown')}"
    elif alert_type == "sensitive-file-write":
        hook = body.get("function_name", "unknown")
    else:
        hook = "process_exec"

    detail = get_policy_detail(alert_type, body)

    return {
        "type": alert_type,
        "severity": SEVERITY[alert_type],
        "timestamp": event.get("time", "unknown"),
        "node": event.get("node_name", "unknown"),
        "pod": pod.get("name", "host or unavailable"),
        "namespace": pod.get("namespace", "unavailable"),
        "container_id": container.get("id", "unavailable"),
        "image": image.get("name", "unavailable"),
        "image_digest": digest,
        "binary": binary,
        "command": command,
        "parent": parent.get("binary", "unavailable"),
        "uid": credentials.get("uid", process.get("uid", "unknown")),
        "gid": credentials.get("gid", "unknown"),
        "pid": process.get("pid", "unknown"),
        "hook": hook,
        "detail": detail,
        "policy": body.get("policy_name", "not applicable"),
    }


def slack_payload(alert):
    title = {
        "shell-execution": "Container shell execution",
        "namespace-escape": "Namespace escape detection",
        "sensitive-file-write": "Sensitive-file write-capable open",
    }[alert["type"]]

    fields = [
        ("Severity", alert["severity"]),
        ("Timestamp", alert["timestamp"]),
        ("Node", alert["node"]),
        ("Namespace", alert["namespace"]),
        ("Pod", alert["pod"]),
        ("Container ID", alert["container_id"]),
        ("Image", alert["image"]),
        ("Image digest", alert["image_digest"]),
        ("Process", alert["binary"]),
        ("Parent process", alert["parent"]),
        ("Command", alert["command"]),
        ("UID / GID", f"{alert['uid']} / {alert['gid']}"),
        ("PID", str(alert["pid"])),
        ("Syscall / hook", alert["hook"]),
        ("Policy", alert["policy"]),
    ]

    header_block = {
        "type": "header",
        "text": {"type": "plain_text", "text": f"🚨 Tetragon: {title}"},
    }

    # Slack permits at most 10 fields in each section block.
    field_blocks = [
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*{name}*\n{str(value)[:900]}",
                }
                for name, value in fields[index:index + 10]
            ],
        }
        for index in range(0, len(fields), 10)
    ]

    detail_block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Detection details*\n{alert['detail'][:2500]}",
        },
    }

    context_block = {
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "Source: Tetragon eBPF runtime security telemetry",
            }
        ],
    }

    blocks = [header_block] + field_blocks + [detail_block, context_block]
    return {"blocks": blocks}


def send_slack(alert, webhook):
    payload = json.dumps(slack_payload(alert)).encode("utf-8")
    request = urllib.request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                result = response.read().decode("utf-8", errors="replace")
                if response.status == 200 and result.strip() == "ok":
                    LOG.info("Slack delivery successful: %s", alert["type"])
                    return True
                LOG.error("Slack returned an unexpected response")
        except (urllib.error.URLError, TimeoutError, OSError):
            LOG.exception("Slack delivery attempt %s failed", attempt)

        if attempt < 3:
            time.sleep(2 ** attempt)

    return False


def event_key(event, alert_type, body):
    process = body.get("process", {})
    return (
        alert_type,
        event.get("time"),
        process.get("exec_id"),
        process.get("pid"),
        body.get("policy_name"),
        body.get("function_name"),
    )


def run(args):
    webhook = os.environ.get("SLACK_WEBHOOK_URL")

    if not args.dry_run:
        if not webhook or not webhook.startswith(
            "https://hooks.slack.com/services/"
        ):
            LOG.error("A valid SLACK_WEBHOOK_URL environment variable is required")
            return 2

    command = [
        K3S, "kubectl", "exec",
        "-n", "tetragon",
        "daemonset/tetragon",
        "-c", "tetragon",
        "--",
        "tetra",
        "--server-address", SOCKET,
        "getevents",
        "--reconnect",
        "-o", "json",
    ]

    LOG.info("Starting Tetragon gRPC event stream")

    try:
        stream = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )
    except OSError:
        LOG.exception("Could not start Tetragon gRPC client")
        return 1

    recent = set()
    order = deque()
    handled = 0

    try:
        for line in stream.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                LOG.warning("Ignoring non-JSON line from event stream")
                continue

            alert_type, body = get_alert_type(event)
            if not alert_type:
                continue

            key = event_key(event, alert_type, body)
            if key in recent:
                continue

            recent.add(key)
            order.append(key)

            if len(order) > 4096:
                recent.discard(order.popleft())

            alert = build_alert(event, alert_type, body)

            if args.dry_run:
                print(json.dumps(alert, indent=2), flush=True)
            else:
                send_slack(alert, webhook)

            handled += 1
            if args.max_events and handled >= args.max_events:
                LOG.info("Reached maximum event count")
                break

    except KeyboardInterrupt:
        LOG.info("Bridge interrupted")
    finally:
        stream.terminate()
        try:
            stream.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stream.kill()
            stream.wait()

    return 0


def main():
    parser = argparse.ArgumentParser(description="Tetragon Slack ChatOps bridge")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print alerts without sending them to Slack",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="Stop after this many matching alerts; zero means unlimited",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    sys.exit(run(args))


if __name__ == "__main__":
    main()
