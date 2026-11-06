#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "scripts")
)
from chaos_guard import validate_request

NAMESPACE = "loki"
STATEFULSET = "loki"
POD = "loki-0"
PVC = "storage-loki-0"

ALLOY_NAMESPACE = "observability"
ALLOY_DS = "alloy"

TETRAGON_NAMESPACE = "tetragon"
TETRAGON_DS = "tetragon"

K3S = "/usr/local/bin/k3s"
FAULT_SECONDS = 15
RECOVERY_TIMEOUT = 180
WATCHDOG_SECONDS = 240

RESULT_DIR = Path(__file__).resolve().parents[1] / "results"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def run(command, check=True, timeout=60):
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=timeout
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\n{result.stderr}"
        )
    return result


def kubectl(*args, check=True):
    return run(["sudo", K3S, "kubectl", *args], check=check)


def systemctl(*args, check=True):
    return run(["sudo", "systemctl", *args], check=check)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_baseline():
    node = kubectl(
        "get", "nodes",
        "-o",
        "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}"
    )
    require(node.stdout.strip() == "True", "Kubernetes node is not Ready")

    sts = kubectl(
        "get", "statefulset", STATEFULSET, "-n", NAMESPACE,
        "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}"
    )
    require(sts.stdout.strip() == "1:1", "Loki must be 1/1 ready")

    pvc = kubectl(
        "get", "pvc", PVC, "-n", NAMESPACE,
        "-o", "jsonpath={.status.phase}"
    )
    require(pvc.stdout.strip() == "Bound", "Loki PVC is not Bound")

    pod = kubectl(
        "get", "pod", POD, "-n", NAMESPACE,
        "-o", "jsonpath={.status.phase}:{.status.containerStatuses[0].ready}"
    )
    require(pod.stdout.strip() == "Running:true", "Loki pod is not healthy")

    alloy = kubectl(
        "get", "daemonset", ALLOY_DS, "-n", ALLOY_NAMESPACE,
        "-o", "jsonpath={.status.desiredNumberScheduled}:{.status.numberReady}"
    )
    require(alloy.stdout.strip() == "1:1", "Alloy DaemonSet is not ready")

    tetragon = kubectl(
        "get", "daemonset", TETRAGON_DS, "-n", TETRAGON_NAMESPACE,
        "-o", "jsonpath={.status.desiredNumberScheduled}:{.status.numberReady}"
    )
    require(tetragon.stdout.strip() == "1:1", "Tetragon DaemonSet is not ready")

    return {
        "pvc_phase": pvc.stdout.strip(),
        "alloy_ready": alloy.stdout.strip(),
        "tetragon_ready": tetragon.stdout.strip(),
    }


def wait_for_pod_absent(timeout=60):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        result = kubectl(
            "get", "pod", POD, "-n", NAMESPACE,
            "-o", "name", check=False
        )

        if result.returncode != 0:
            if "NotFound" in result.stderr:
                return
            raise RuntimeError(
                "Could not verify Loki pod absence; kubectl returned an "
                f"unexpected error: {result.stderr}"
            )

        if not result.stdout.strip():
            return

        time.sleep(1)

    raise TimeoutError("Loki pod did not disappear after scaling down")


def wait_for_recovery():
    deadline = time.monotonic() + RECOVERY_TIMEOUT

    while time.monotonic() < deadline:
        result = kubectl(
            "get", f"pod/{POD}",
            "-n", NAMESPACE,
            "-o", "jsonpath={.status.containerStatuses[0].ready}",
            check=False
        )

        if result.returncode == 0 and result.stdout.strip() == "true":
            print("Loki pod is Ready.")
            return

        if result.returncode != 0:
            if "NotFound" not in result.stderr:
                raise RuntimeError(
                    f"Unexpected error while checking Loki recovery: {result.stderr}"
                )

        time.sleep(1)

    raise TimeoutError(
        f"Loki pod did not become Ready within {RECOVERY_TIMEOUT} seconds"
    )


def arm_watchdog():
    unit = f"chaos-loki-restore-{os.getpid()}"

    command = [
        "sudo", "/usr/bin/systemd-run",
        f"--unit={unit}",
        f"--on-active={WATCHDOG_SECONDS}s",
        "--description=Emergency Loki replica restoration",
        K3S, "kubectl", "scale",
        f"statefulset/{STATEFULSET}",
        "-n", NAMESPACE,
        "--replicas=1",
    ]

    result = run(command, timeout=30)
    print(result.stdout.strip())

    timer = systemctl("is-active", f"{unit}.timer", check=False)
    require(
        timer.returncode == 0 and timer.stdout.strip() == "active",
        "Restoration watchdog timer is not active. Aborting fault injection."
    )

    print(f"RESTORATION WATCHDOG: ACTIVE ({unit}.timer)")
    print(f"Watchdog deadline: {WATCHDOG_SECONDS} seconds")
    return unit


def cancel_watchdog(unit):
    result = systemctl("stop", f"{unit}.timer", check=False)
    require(
        result.returncode == 0,
        f"Could not stop watchdog timer {unit}.timer: {result.stderr}"
    )
    print("RESTORATION WATCHDOG: CANCELLED after Loki became Ready")


def save_result(result):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    filename = (
        "telemetry-recovery-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ".json"
    )
    output = RESULT_DIR / filename
    output.write_text(json.dumps(result, indent=2) + "\n")
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Controlled Loki backend recovery experiment"
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Actually interrupt Loki and restore it"
    )
    args = parser.parse_args()

    try:
        validate_request(
            experiment="telemetry",
            namespace=NAMESPACE,
            duration=FAULT_SECONDS,
            execute_requested=args.execute,
        )
    except Exception as exc:
        sys.exit(str(exc))

    baseline_state = check_baseline()

    print("BASELINE: PASS")
    print("Node Ready; Loki 1/1; PVC Bound; Alloy 1/1; Tetragon 1/1.")
    print(f"Planned interruption: {FAULT_SECONDS} seconds.")
    print(f"Recovery timeout: {RECOVERY_TIMEOUT} seconds.")
    print(f"Watchdog timeout: {WATCHDOG_SECONDS} seconds.")

    if not args.execute:
        print("DRY RUN ONLY: no Kubernetes resources were changed.")
        return 0

    result = {
        "experiment": "loki_backend_recovery",
        "started_at_utc": timestamp(),
        "planned_outage_seconds": FAULT_SECONDS,
        "recovery_timeout_seconds": RECOVERY_TIMEOUT,
        "watchdog_timeout_seconds": WATCHDOG_SECONDS,
        "baseline_state": baseline_state,
        "pvc_bound_before_and_after": "NOT_MEASURED",
        "alloy_ready_before_and_after": "NOT_MEASURED",
        "tetragon_ready_before_and_after": "NOT_MEASURED",
        "loki_recovered": False,
        "recovered": False,
        "experiment_success": False,
        "restore_command_succeeded": None,
        "post_recovery_checks": "NOT_RUN",
        "watchdog_cancelled_after_recovery": False,
        "injection_error": None,
        "restoration_error": None,
        "recovery_error": None,
    }

    watchdog_unit = None
    scale_attempted = False
    outage_confirmed_at = None
    restore_started_at = None
    restore_started_utc = None
    recovery_time = None
    baseline_check_started = False

    try:
        watchdog_unit = arm_watchdog()
        result["watchdog_unit"] = watchdog_unit

        print("Scaling Loki StatefulSet to zero replicas...")
        scale_attempted = True
        kubectl(
            "scale", f"statefulset/{STATEFULSET}",
            "-n", NAMESPACE, "--replicas=0"
        )

        wait_for_pod_absent()
        outage_confirmed_at = time.monotonic()
        result["outage_confirmed_at_utc"] = timestamp()

        print(f"Loki pod absent. Holding outage for {FAULT_SECONDS} seconds...")
        time.sleep(FAULT_SECONDS)

    except Exception as exc:
        result["injection_error"] = str(exc)
        print(f"FAULT INJECTION ERROR: {exc}", file=sys.stderr)

    finally:
        if scale_attempted:
            print("Issuing Loki restoration command...")
            restore_started_at = time.monotonic()
            restore_started_utc = timestamp()

            try:
                kubectl(
                    "scale", f"statefulset/{STATEFULSET}",
                    "-n", NAMESPACE, "--replicas=1"
                )
                result["restore_command_succeeded"] = True

            except Exception as exc:
                result["restore_command_succeeded"] = False
                result["restoration_error"] = str(exc)
                print(
                    f"RESTORATION COMMAND FAILED: {exc}",
                    file=sys.stderr
                )

    if scale_attempted and result["restoration_error"] is None:
        try:
            print("Waiting for Loki readiness...")
            wait_for_recovery()

            recovery_time = round(time.monotonic() - restore_started_at, 3)
            result["loki_recovered"] = True

            if watchdog_unit:
                try:
                    cancel_watchdog(watchdog_unit)
                    result["watchdog_cancelled_after_recovery"] = True
                except Exception as exc:
                    result["recovery_error"] = (
                        f"Watchdog cancellation failed: {exc}"
                    )
                    print(result["recovery_error"], file=sys.stderr)

            baseline_check_started = True
            try:
                post_recovery_state = check_baseline()
                result["post_recovery_state"] = post_recovery_state

                result["pvc_bound_before_and_after"] = (
                    baseline_state["pvc_phase"] == "Bound"
                    and post_recovery_state["pvc_phase"] == "Bound"
                )
                result["alloy_ready_before_and_after"] = (
                    baseline_state["alloy_ready"]
                    == post_recovery_state["alloy_ready"]
                    == "1:1"
                )
                result["tetragon_ready_before_and_after"] = (
                    baseline_state["tetragon_ready"]
                    == post_recovery_state["tetragon_ready"]
                    == "1:1"
                )

                require(
                    result["pvc_bound_before_and_after"],
                    "Loki PVC was not preserved as Bound"
                )
                require(
                    result["alloy_ready_before_and_after"],
                    "Alloy readiness changed after recovery"
                )
                require(
                    result["tetragon_ready_before_and_after"],
                    "Tetragon readiness changed after recovery"
                )

                result["post_recovery_checks"] = "PASS"

            except Exception as exc:
                result["post_recovery_checks"] = "FAILED"
                if result["recovery_error"]:
                    result["recovery_error"] += f"; baseline checks failed: {exc}"
                else:
                    result["recovery_error"] = (
                        f"Baseline checks failed: {exc}"
                    )
                print(result["recovery_error"], file=sys.stderr)

        except Exception as exc:
            if result["recovery_error"]:
                result["recovery_error"] += f"; readiness check failed: {exc}"
            else:
                result["recovery_error"] = str(exc)
            print(
                f"LOKI RECOVERY CHECK FAILED: {exc}",
                file=sys.stderr
            )

    elif result["restoration_error"] is not None:
        print(
            "Watchdog remains armed as the independent restoration fallback.",
            file=sys.stderr
        )

    result.update({
        "restore_started_at_utc": restore_started_utc,
        "actual_outage_duration_seconds": (
            round(restore_started_at - outage_confirmed_at, 3)
            if restore_started_at is not None
            and outage_confirmed_at is not None else None
        ),
        "recovery_time_seconds_after_restore": recovery_time,
        "recovered": (
            result["loki_recovered"]
            and result["post_recovery_checks"] == "PASS"
            and result["watchdog_cancelled_after_recovery"]
        ),
        "completed_at_utc": timestamp(),
    })

    errors = [
        result[key]
        for key in ("injection_error", "restoration_error", "recovery_error")
        if result[key]
    ]

    result["experiment_success"] = (
        scale_attempted
        and not errors
        and result["recovered"]
    )

    if not result["experiment_success"] and not errors:
        errors.append("Experiment did not complete all required stages.")

    result["error"] = "; ".join(errors) if errors else None

    output = save_result(result)

    print("\nEXPERIMENT RESULT")
    print(json.dumps(result, indent=2))
    print(f"Saved: {output}")

    return 0 if result["experiment_success"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(
            "\nINTERRUPTED. Check Loki immediately. If necessary, restore it with:\n"
            "sudo /usr/local/bin/k3s kubectl scale statefulset/loki "
            "-n loki --replicas=1",
            file=sys.stderr
        )
        sys.exit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "Check Loki replicas immediately. Emergency restore command:\n"
            "sudo /usr/local/bin/k3s kubectl scale statefulset/loki "
            "-n loki --replicas=1",
            file=sys.stderr
        )
        sys.exit(1)
