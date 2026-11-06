#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "scripts")
)
from chaos_guard import validate_request

NAMESPACE = "tetragon"
DAEMONSET = "tetragon"
SELECTOR = "app.kubernetes.io/instance=tetragon,app.kubernetes.io/name=tetragon"
TIMEOUT = 60
RESULTS = Path(__file__).resolve().parents[1] / "results"

KUBECTL = ["sudo", "k3s", "kubectl"]


def kubectl(*args):
    result = subprocess.run(
        KUBECTL + list(args),
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def get_state():
    ds = json.loads(kubectl(
        "get", "daemonset", DAEMONSET, "-n", NAMESPACE, "-o", "json"
    ))
    pods = json.loads(kubectl(
        "get", "pods", "-n", NAMESPACE,
        "-l", SELECTOR, "-o", "json"
    ))

    return ds, pods["items"]


def ready(pod):
    return (
        pod.get("status", {}).get("phase") == "Running"
        and any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in pod.get("status", {}).get("conditions", [])
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Measure Tetragon DaemonSet agent self-recovery."
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Delete the single verified Tetragon agent pod.",
    )
    args = parser.parse_args()

    try:
        validate_request(
            experiment="tetragon",
            namespace=NAMESPACE,
            duration=TIMEOUT,
            execute_requested=args.execute,
        )
    except (PermissionError, OSError, ValueError) as exc:
        sys.exit(str(exc))

    print("========== TETRAGON RECOVERY EXPERIMENT ==========")

    try:
        ds, pods = get_state()
    except Exception as exc:
        sys.exit(f"BLOCKED: Kubernetes inspection failed: {exc}")

    desired = ds["status"].get("desiredNumberScheduled", 0)
    available = ds["status"].get("numberReady", 0)
    current = ds["status"].get("currentNumberScheduled", 0)

    healthy_pods = [p for p in pods if ready(p)]

    if desired != 1 or available != 1 or current != 1:
        sys.exit("BLOCKED: expected exactly one Ready DaemonSet agent.")

    if len(pods) != 1 or len(healthy_pods) != 1:
        sys.exit("BLOCKED: expected exactly one healthy Tetragon pod.")

    old_pod = healthy_pods[0]["metadata"]["name"]

    print(f"Namespace:       {NAMESPACE}")
    print(f"DaemonSet:       {DAEMONSET}")
    print(f"Current pod:     {old_pod}")
    print(f"Ready replicas:  {available}/{desired}")
    print(f"Recovery limit:  {TIMEOUT}s")

    if not args.execute:
        print("DRY RUN: target and preconditions verified.")
        print("No Kubernetes resources were changed.")
        print("Use --execute only when ready to interrupt runtime monitoring.")
        return

    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()

    print("\nDeleting the verified agent pod...")
    kubectl("delete", "pod", old_pod, "-n", NAMESPACE, "--wait=false")

    recovered_pod = None

    while time.monotonic() - started < TIMEOUT:
        try:
            _, current_pods = get_state()
            candidates = [
                p for p in current_pods
                if p["metadata"]["name"] != old_pod and ready(p)
            ]
            if candidates:
                recovered_pod = candidates[0]["metadata"]["name"]
                break
        except Exception as exc:
            print(f"Recovery check warning: {exc}")

        time.sleep(2)

    elapsed = round(time.monotonic() - started, 3)
    success = recovered_pod is not None

    record = {
        "experiment": "tetragon-agent-recovery",
        "started_at_utc": started_at,
        "namespace": NAMESPACE,
        "daemonset": DAEMONSET,
        "terminated_pod": old_pod,
        "replacement_pod": recovered_pod,
        "recovery_time_seconds": elapsed if success else None,
        "timeout_seconds": TIMEOUT,
        "recovered": success,
    }

    RESULTS.mkdir(parents=True, exist_ok=True)
    output = RESULTS / (
        "tetragon-recovery-" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
    )
    output.write_text(json.dumps(record, indent=2) + "\n")

    print("\n========== EXPERIMENT RESULT ==========")
    print(json.dumps(record, indent=2))
    print(f"Result saved: {output}")

    if not success:
        sys.exit(
            "RECOVERY TIMEOUT: agent did not become Ready within 60 seconds. "
            "Do not repeat the experiment; investigate the DaemonSet."
        )


if __name__ == "__main__":
    main()
