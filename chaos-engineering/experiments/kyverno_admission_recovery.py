#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import signal
import time
import os
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from chaos_guard import validate_request

K3S = "/usr/local/bin/k3s"
NAMESPACE = "kyverno"
DEPLOYMENT = "kyverno-admission-controller"
SERVICE = "kyverno-svc"
TEST_NAMESPACE = "phase8-test"
PREFLIGHT_IMAGE = "ghcr.io/idamacybersecurity/devsecops-unsigned-test:latest"

FAULT_SECONDS = 10
RECOVERY_TIMEOUT = 120
WATCHDOG_SECONDS = 180

RESULT_DIR = Path(__file__).resolve().parents[1] / "results"


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def run(command, check=True, timeout=45, input_text=None):
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\n{result.stderr.strip()}"
        )
    return result


def kubectl(*args, check=True, timeout=45):
    return run(["sudo", K3S, "kubectl", *args], check=check, timeout=timeout)


def systemctl(*args, check=True):
    return run(["sudo", "systemctl", *args], check=check, timeout=30)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def get_value(*args):
    return kubectl(*args).stdout.strip()


def get_service_endpoint_state():
    """Read both legacy Endpoints and EndpointSlices; fail on query or parse errors."""
    legacy = kubectl(
        "get", "endpoints", SERVICE, "-n", NAMESPACE,
        "-o", "json", check=False, timeout=3,
    )
    slices = kubectl(
        "get", "endpointslices", "-n", NAMESPACE,
        "-l", f"kubernetes.io/service-name={SERVICE}",
        "-o", "json", check=False, timeout=3,
    )

    if legacy.returncode != 0:
        raise RuntimeError(
            "Could not inspect legacy Endpoints: " + legacy.stderr.strip()
        )
    if slices.returncode != 0:
        raise RuntimeError(
            "Could not inspect EndpointSlices: " + slices.stderr.strip()
        )

    try:
        legacy_data = json.loads(legacy.stdout)
        slice_data = json.loads(slices.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid endpoint JSON: {exc}") from exc

    subsets = legacy_data.get("subsets", [])
    items = slice_data.get("items", [])

    if not isinstance(subsets, list) or not isinstance(items, list):
        raise RuntimeError("Unexpected Kubernetes endpoint response structure")

    legacy_addresses = [
        address["ip"]
        for subset in subsets
        for address in subset.get("addresses", [])
        if isinstance(address, dict) and address.get("ip")
    ]

    slice_addresses = [
        address
        for item in items
        for endpoint in (item.get("endpoints") or [])
        if endpoint.get("conditions", {}).get("ready") is True
        for address in endpoint.get("addresses", [])
    ]

    return {
        "legacy_ready_addresses": legacy_addresses,
        "legacy_ready_count": len(legacy_addresses),
        "slice_ready_addresses": slice_addresses,
        "slice_ready_count": len(slice_addresses),
    }


def check_controller_ready():
    state = get_value(
        "get", "deployment", DEPLOYMENT, "-n", NAMESPACE,
        "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}"
    )
    require(state == "1:1", f"Kyverno controller must be 1/1 ready; got {state}")

    endpoint_state = get_service_endpoint_state()
    require(
        endpoint_state["legacy_ready_count"] > 0,
        "Kyverno legacy Endpoints has no ready addresses",
    )
    require(
        endpoint_state["slice_ready_count"] > 0,
        "Kyverno EndpointSlices has no ready addresses",
    )

    node = get_value(
        "get", "nodes",
        "-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}"
    )
    require(node == "True", "Kubernetes node is not Ready")

    return {
        "deployment_replicas_ready": state,
        "service_endpoints_present": True,
        "service_endpoint_state": endpoint_state,
        "node_ready": True,
    }


def make_deployment_payload(name, image):
    return json.dumps({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": TEST_NAMESPACE,
            "labels": {"app": "kyverno-chaos-admission-test"},
        },
        "spec": {
            "replicas": 0,
            "selector": {
                "matchLabels": {"app": "kyverno-chaos-admission-test"}
            },
            "template": {
                "metadata": {
                    "labels": {"app": "kyverno-chaos-admission-test"}
                },
                "spec": {
                    "containers": [{
                        "name": "admission-check",
                        "image": image,
                        "command": ["/bin/sh", "-c", "true"],
                    }],
                },
            },
        },
    })


def admission_request(name, image, timeout=45):
    payload = make_deployment_payload(name, image)
    started = time.monotonic()
    result = run(
        ["sudo", K3S, "kubectl", "create", "-f", "-",
         "--dry-run=server", "-o", "name"],
        check=False,
        timeout=timeout,
        input_text=payload,
    )
    elapsed = round(time.monotonic() - started, 3)
    return {
        "name": name,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "elapsed_seconds": elapsed,
        "outcome": "ACCEPTED" if result.returncode == 0 else "REJECTED_OR_ERROR",
    }


def wait_for_apiserver_webhook_unavailable(image, suffix, fault_window_started, timeout=3.0):
    """
    Confirm that the API server itself observes the Kyverno endpoint outage.
    Use server-side dry-run canaries; require two consecutive fail-closed
    webhook-unavailable responses before starting the measured requests.
    """
    deadline = min(
        time.monotonic() + timeout,
        fault_window_started + FAULT_SECONDS - 3.0,
    )
    consecutive_failures = 0
    observations = []

    while time.monotonic() < deadline:
        name = f"kyverno-preflight-{suffix}-{len(observations) + 1}"
        response = admission_request(name, image, timeout=3)
        stderr = response["stderr"].lower()

        expected_failure = (
            response["returncode"] != 0
            and "no endpoints available for service" in stderr
            and "kyverno-svc" in stderr
        )

        observations.append({
            "name": name,
            "returncode": response["returncode"],
            "outcome": (
                "FAIL_CLOSED_WEBHOOK_UNAVAILABLE"
                if expected_failure
                else response["outcome"]
            ),
            "stderr": response["stderr"],
        })

        if expected_failure:
            consecutive_failures += 1
            if consecutive_failures >= 2:
                return {
                    "passed": True,
                    "consecutive_fail_closed_responses": consecutive_failures,
                    "observations": observations,
                }
        else:
            consecutive_failures = 0

            if response["returncode"] != 0:
                raise RuntimeError(
                    "API-server preflight returned an unexpected error: "
                    + response["stderr"]
                )

        time.sleep(0.2)

    raise TimeoutError(
        "Could not confirm two consecutive API-server fail-closed "
        "responses within the safe preflight window. Observations: "
        + json.dumps(observations)
    )


def get_service_selector():
    raw = kubectl(
        "get", "service", SERVICE, "-n", NAMESPACE, "-o", "json"
    ).stdout
    service = json.loads(raw)
    selector = service.get("spec", {}).get("selector")
    require(
        isinstance(selector, dict) and bool(selector),
        "Kyverno Service has no usable selector; refusing to inject a fault",
    )
    return selector


def patch_service_selector(selector):
    require(
        isinstance(selector, dict) and bool(selector),
        "Refusing to apply an empty or invalid Kyverno Service selector",
    )
    patch = json.dumps(
        [{"op": "replace", "path": "/spec/selector", "value": selector}],
        separators=(",", ":"),
    )
    return kubectl(
        "patch", "service", SERVICE, "-n", NAMESPACE,
        "--type=json", "-p", patch, timeout=5,
    )


def restart_single_admission_controller_pod():
    """Gracefully restart exactly one ready pod selected by the Deployment."""
    deployment = kubectl(
        "get", "deployment", DEPLOYMENT, "-n", NAMESPACE, "-o", "json"
    )
    deployment_data = json.loads(deployment.stdout)
    selector = deployment_data.get("spec", {}).get("selector", {})
    match_labels = selector.get("matchLabels", {})
    match_expressions = selector.get("matchExpressions", [])

    require(
        bool(match_labels) and not match_expressions,
        "Refusing pod restart: Deployment selector is empty or uses "
        "unsupported matchExpressions",
    )

    selector_arg = ",".join(
        f"{key}={value}" for key, value in sorted(match_labels.items())
    )
    pods_result = kubectl(
        "get", "pods", "-n", NAMESPACE, "-l", selector_arg, "-o", "json"
    )
    pods = json.loads(pods_result.stdout).get("items", [])

    ready_pods = []
    for pod in pods:
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})
        ready = any(
            condition.get("type") == "Ready"
            and condition.get("status") == "True"
            for condition in status.get("conditions", [])
        )
        if (
            metadata.get("deletionTimestamp") is None
            and status.get("phase") == "Running"
            and ready
        ):
            ready_pods.append(metadata.get("name"))

    require(
        len(ready_pods) == 1 and ready_pods[0],
        "Refusing pod restart: expected exactly one ready admission "
        f"controller pod, found {ready_pods}",
    )

    pod_name = ready_pods[0]
    print(f"Restarting the single ready admission-controller pod: {pod_name}")

    kubectl(
        "delete", "pod", pod_name, "-n", NAMESPACE,
        "--grace-period=1", "--wait=true", "--timeout=3s",
        timeout=5,
    )
    print(f"Admission-controller pod deletion completed: {pod_name}")
    return pod_name


def wait_for_controller_absence(timeout=10, stable_seconds=1.0):
    deadline = time.monotonic() + timeout
    stable_since = None
    last_state = "unknown"

    while time.monotonic() < deadline:
        replicas = kubectl(
            "get", "deployment", DEPLOYMENT, "-n", NAMESPACE,
            "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}",
            check=False, timeout=2,
        )

        if replicas.returncode != 0:
            raise RuntimeError(
                "Could not inspect Kyverno controller readiness: "
                + replicas.stderr.strip()
            )

        endpoint_state = get_service_endpoint_state()
        last_state = (
            f"deployment={replicas.stdout.strip()}, "
            f"endpoint_state={json.dumps(endpoint_state)}"
        )

        healthy_controller = replicas.stdout.strip() == "1:1"
        no_endpoints = (
            endpoint_state["legacy_ready_count"] == 0
            and endpoint_state["slice_ready_count"] == 0
        )

        if healthy_controller and no_endpoints:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= stable_seconds:
                print(
                    f"Legacy Endpoints and EndpointSlices remained empty "
                    f"for {stable_seconds:.1f}s."
                )
                return
        else:
            stable_since = None

        time.sleep(0.2)

    raise TimeoutError(
        "Kyverno endpoints did not remain absent in both endpoint APIs "
        f"while its controller remained ready; {last_state}"
    )


def _arm_selector_restore(unit, delay_seconds, selector, description):
    patch = json.dumps(
        [{"op": "replace", "path": "/spec/selector", "value": selector}],
        separators=(",", ":"),
    )
    command = [
        "sudo", "/usr/bin/systemd-run",
        f"--unit={unit}",
        f"--on-active={delay_seconds}s",
        "--timer-property=AccuracySec=1s",
        "--property=RemainAfterExit=yes",
        f"--description={description}",
        K3S, "kubectl", "patch", "service", SERVICE,
        "-n", NAMESPACE, "--type=json", "-p", patch,
    ]
    result = run(command, timeout=20)
    print(result.stdout.strip())

    timer = systemctl("is-active", f"{unit}.timer", check=False)
    require(
        timer.returncode == 0 and timer.stdout.strip() == "active",
        f"Restoration timer {unit}.timer is not active; aborting fault injection",
    )
    print(f"SELECTOR RESTORATION TIMER ACTIVE: {unit}.timer")
    return unit


def arm_watchdog(original_selector):
    unit = f"chaos-kyverno-restore-{os.getpid()}"
    return _arm_selector_restore(
        unit,
        WATCHDOG_SECONDS,
        original_selector,
        "Emergency restoration of Kyverno admission Service selector",
    )


def arm_deadline_restore(original_selector):
    unit = f"chaos-kyverno-deadline-restore-{os.getpid()}"
    return _arm_selector_restore(
        unit,
        FAULT_SECONDS,
        original_selector,
        "Independent deadline restoration of Kyverno admission Service selector",
    )


def wait_for_recovery():
    deadline = time.monotonic() + RECOVERY_TIMEOUT
    last_state = "unknown"

    while time.monotonic() < deadline:
        deployment = kubectl(
            "get", "deployment", DEPLOYMENT, "-n", NAMESPACE,
            "-o", "jsonpath={.spec.replicas}:{.status.readyReplicas}",
            check=False, timeout=3,
        )

        if deployment.returncode != 0:
            raise RuntimeError(
                "Could not inspect Kyverno controller during recovery: "
                + deployment.stderr.strip()
            )

        endpoint_state = get_service_endpoint_state()
        last_state = (
            f"deployment={deployment.stdout.strip()}, "
            f"endpoint_state={json.dumps(endpoint_state)}"
        )

        if (
            deployment.stdout.strip() == "1:1"
            and endpoint_state["legacy_ready_count"] > 0
            and endpoint_state["slice_ready_count"] > 0
        ):
            print(
                "Recovery verified: legacy Endpoints and EndpointSlices "
                "both have ready addresses."
            )
            return

        time.sleep(0.5)

    raise TimeoutError(
        f"Kyverno Service endpoints did not recover in both endpoint APIs "
        f"within {RECOVERY_TIMEOUT}s; {last_state}"
    )


def _stop_and_classify_timer(unit, description):
    def properties(result):
        parsed = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                parsed[key] = value
        return parsed

    def inspect_service():
        result = systemctl(
            "show", f"{unit}.service",
            "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
            "-p", "Result", "-p", "ExecMainStartTimestamp",
            check=False,
        )
        return result, properties(result)

    def classify_fired_service(result, service):
        started = service.get("ExecMainStartTimestamp", "").strip()
        if not started or started == "n/a":
            return False

        require(
            result.returncode == 0
            and service.get("LoadState") == "loaded"
            and service.get("ActiveState") == "active"
            and service.get("SubState") == "exited"
            and service.get("Result") == "success",
            f"{description} service ran but successful restoration "
            "could not be verified",
        )
        return True

    # A fired transient timer may already be unloaded. Check its service first.
    service_result, service = inspect_service()
    if classify_fired_service(service_result, service):
        return "FIRED_SUCCESSFULLY"

    require(
        service_result.returncode == 0
        and service.get("ActiveState") in ("inactive", "")
        and service.get("ExecMainStartTimestamp", "").strip() in ("", "n/a"),
        f"{description} service state is indeterminate before cancellation",
    )

    timer_before_result = systemctl(
        "show", f"{unit}.timer",
        "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
        check=False,
    )
    timer_before = properties(timer_before_result)

    require(
        timer_before_result.returncode == 0
        and timer_before.get("LoadState") == "loaded"
        and timer_before.get("ActiveState") == "active",
        f"{description} timer was not confirmed active before cancellation",
    )

    stop_result = systemctl("stop", f"{unit}.timer", check=False)

    timer_after_result = systemctl(
        "show", f"{unit}.timer",
        "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
        check=False,
    )
    timer_after = properties(timer_after_result)

    service_result, service = inspect_service()

    # The timer could fire in the interval between inspection and cancellation.
    if classify_fired_service(service_result, service):
        return "FIRED_SUCCESSFULLY"

    require(
        stop_result.returncode == 0,
        f"Could not stop {description} timer: {stop_result.stderr}",
    )
    require(
        timer_after_result.returncode == 0
        and (
            timer_after.get("LoadState") == "not-found"
            or (
                timer_after.get("LoadState") == "loaded"
                and timer_after.get("ActiveState") == "inactive"
            )
        ),
        f"{description} timer stop could not be verified",
    )
    require(
        service_result.returncode == 0
        and service.get("ActiveState") in ("inactive", "")
        and service.get("ExecMainStartTimestamp", "").strip() in ("", "n/a"),
        f"{description} service state is indeterminate after cancellation",
    )
    return "CANCELLED_BEFORE_DEADLINE"

def cancel_watchdog(unit):
    outcome = _stop_and_classify_timer(unit, "Kyverno restoration watchdog")
    require(
        outcome == "CANCELLED_BEFORE_DEADLINE",
        "Emergency watchdog fired before normal restoration completed",
    )
    print("RESTORATION WATCHDOG CANCELLED AFTER VERIFIED RECOVERY")


def retire_deadline_restore(unit):
    outcome = _stop_and_classify_timer(unit, "Kyverno deadline restoration")
    print(f"INDEPENDENT DEADLINE RESTORATION: {outcome}")
    return outcome


def save_result(result):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    filename = (
        "kyverno-admission-recovery-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ".json"
    )
    output = RESULT_DIR / filename
    output.write_text(json.dumps(result, indent=2) + "\n")
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Controlled Kyverno admission Service-unavailability experiment"
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Interrupt Kyverno admission Service endpoint selection for up to 10 seconds",
    )
    args = parser.parse_args()

    try:
        validate_request(
            experiment="kyverno",
            namespace=NAMESPACE,
            duration=FAULT_SECONDS,
            execute_requested=args.execute,
        )
    except Exception as exc:
        sys.exit(str(exc))

    baseline = check_controller_ready()
    image = get_value(
        "get", "pod", "signed-api-test", "-n", TEST_NAMESPACE,
        "-o", "jsonpath={.spec.containers[0].image}"
    )
    require(
        "@sha256:" in image,
        "Known-good signed-api-test image must be digest-pinned",
    )

    suffix = datetime.now(timezone.utc).strftime("%H%M%S")
    baseline_request = admission_request(
        f"kyverno-baseline-{suffix}", image
    )
    require(
        baseline_request["returncode"] == 0,
        "Baseline server-side admission request failed; no fault will be injected",
    )

    print("BASELINE: PASS")
    print(f"Controller: {baseline['deployment_replicas_ready']}")
    print(f"Baseline admission latency: {baseline_request['elapsed_seconds']}s")
    print(f"Planned Service endpoint interruption: up to {FAULT_SECONDS}s")
    print(f"Recovery timeout: {RECOVERY_TIMEOUT}s")

    if not args.execute:
        print("DRY RUN ONLY: no Kubernetes resources were changed.")
        return 0

    original_selector = get_service_selector()
    fault_selector = dict(original_selector)
    fault_selector["chaos.devsecops.local/selector-fault"] = (
        f"disabled-{suffix}"
    )

    result = {
        "experiment": "kyverno_admission_service_unavailability",
        "started_at_utc": timestamp(),
        "namespace": NAMESPACE,
        "test_namespace": TEST_NAMESPACE,
        "fault_method": "existing_service_selector_mismatch",
        "fault_duration_limit_seconds": FAULT_SECONDS,
        "recovery_timeout_seconds": RECOVERY_TIMEOUT,
        "baseline_state": baseline,
        "baseline_admission_request": baseline_request,
        "image_tested": image,
        "original_service_selector": original_selector,
        "fault_service_selector": fault_selector,
        "fault_injected": False,
        "controller_remained_ready": False,
        "controller_pod_restart_requested": False,
        "controller_pod_name": None,
        "controller_recovered_ready": False,
        "admission_requests_during_outage": [],
        "apiserver_endpoint_preflight": None,
        "apiserver_endpoint_preflight_error": None,
        "restore_command_succeeded": None,
        "service_endpoints_recovered": False,
        "post_recovery_admission_request": None,
        "watchdog_cancelled": False,
        "experiment_success": False,
        "errors": [],
    }

    watchdog = None
    deadline_restore = None
    selector_change_attempted = False
    fault_window_started = None
    outage_started = None
    restore_started = None
    restore_completed_at = None
    recovery_completed_at = None
    pending_requests = []

    try:
        watchdog = arm_watchdog(original_selector)
        result["watchdog_unit"] = watchdog

        # Arm the independent deadline before starting the fault clock.
        deadline_restore = arm_deadline_restore(original_selector)
        result["deadline_restore_timer_unit"] = deadline_restore

        fault_window_started = time.monotonic()
        result["fault_window_clock_started_at_utc"] = timestamp()

        print("Interrupting the existing Kyverno Service selector...")
        selector_change_attempted = True
        result["selector_change_requested_at_utc"] = timestamp()
        patch_service_selector(fault_selector)

        remaining = FAULT_SECONDS - (time.monotonic() - fault_window_started)
        require(
            remaining > 1,
            "Insufficient safe fault-window time remains to verify endpoint removal",
        )

        wait_for_controller_absence(timeout=min(3, remaining - 1))
        outage_started = time.monotonic()
        result["outage_confirmed_at_utc"] = timestamp()
        result["fault_injected"] = True
        result["controller_remained_ready"] = False

        restarted_pod = restart_single_admission_controller_pod()
        result["controller_pod_restart_requested"] = True
        result["controller_pod_name"] = restarted_pod

        print(
            "Kyverno Service endpoints are empty and the previous "
            "admission-controller pod has been terminated."
        )

        print(
            "Checking API-server webhook endpoint propagation with "
            "server-side dry-run preflight requests..."
        )
        try:
            result["apiserver_endpoint_preflight"] = (
                wait_for_apiserver_webhook_unavailable(
                    image, suffix, fault_window_started
                )
            )
        except Exception as exc:
            result["apiserver_endpoint_preflight_error"] = str(exc)
            raise

        print(
            "API-server preflight PASS: two consecutive fail-closed "
            "webhook-unavailable responses."
        )

        request_count = 5
        print(f"Submitting {request_count} concurrent Deployment admission requests...")

        for index in range(1, request_count + 1):
            request_name = f"kyverno-outage-{suffix}-{index}"
            payload = make_deployment_payload(request_name, image)

            process = subprocess.Popen(
                ["sudo", "-n", K3S, "kubectl", "create", "-f", "-",
                 "--dry-run=server", "-o", "name"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

            request = {
                "name": request_name,
                "process": process,
                "started_at": time.monotonic(),
                "completed_at": None,
            }
            pending_requests.append(request)

            process.stdin.write(payload)
            process.stdin.close()
            process.stdin = None

        # Restore two seconds before the independent 10-second deadline.
        primary_restore_deadline = fault_window_started + FAULT_SECONDS - 2
        while time.monotonic() < primary_restore_deadline:
            for request in pending_requests:
                if (
                    request["completed_at"] is None
                    and request["process"].poll() is not None
                ):
                    request["completed_at"] = time.monotonic()
            time.sleep(0.1)

    except Exception as exc:
        result["errors"].append(f"Fault/injection stage: {exc}")
        print(f"EXPERIMENT ERROR: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    finally:
        if selector_change_attempted:
            for request in pending_requests:
                if (
                    request["completed_at"] is None
                    and request["process"].poll() is not None
                ):
                    request["completed_at"] = time.monotonic()

            print("RESTORING the original Kyverno Service selector...")
            restore_started = time.monotonic()
            result["restore_started_at_utc"] = timestamp()

            try:
                patch_service_selector(original_selector)
                restore_completed_at = time.monotonic()
                result["restore_command_completed_at_utc"] = timestamp()

                restored_selector = get_service_selector()
                require(
                    restored_selector == original_selector,
                    "Kyverno Service selector does not exactly match "
                    "the saved original selector",
                )
                result["service_selector_restored_exactly"] = True
                result["restore_command_succeeded"] = True
            except Exception as exc:
                result["restore_command_succeeded"] = False
                result["errors"].append(f"Service selector restoration: {exc}")
                print(f"RESTORATION FAILED: {exc}", file=sys.stderr)

    if selector_change_attempted and result["restore_command_succeeded"]:
        try:
            # Cancel the short deadline timer immediately after exact selector
            # restoration; do not wait for EndpointSlice propagation.
            if deadline_restore:
                result["deadline_restore_outcome"] = retire_deadline_restore(
                    deadline_restore
                )
                result["deadline_restore_verified"] = True

            wait_for_recovery()
            recovery_completed_at = time.monotonic()
            result["controller_recovered_ready"] = True
            result["service_endpoints_recovered"] = True
            result["service_recovered_at_utc"] = timestamp()
            result["recovery_time_seconds_after_restore"] = round(
                recovery_completed_at - restore_completed_at, 3
            )

            if watchdog:
                cancel_watchdog(watchdog)
                result["watchdog_cancelled"] = True

            post = admission_request(
                f"kyverno-post-recovery-{suffix}", image
            )
            result["post_recovery_admission_request"] = post
            require(
                post["returncode"] == 0,
                "Post-restoration server-side admission request failed",
            )
            result["post_recovery_checks"] = "PASS"

        except Exception as exc:
            result["errors"].append(f"Recovery verification: {exc}")
            result["post_recovery_checks"] = "FAILED"
            print(f"RECOVERY VERIFICATION ERROR: {exc}", file=sys.stderr)

    elif selector_change_attempted:
        print(
            "Restoration watchdog remains armed; verify the Service selector "
            "and endpoints immediately.",
            file=sys.stderr,
        )

    else:
        # No fault was applied. Cancel any timers that were successfully armed.
        for unit in (deadline_restore, watchdog):
            if unit:
                systemctl("stop", f"{unit}.timer", check=False)

    if pending_requests:
        collection_deadline = time.monotonic() + 40

        for request in pending_requests:
            process = request["process"]

            if request["completed_at"] is None and process.poll() is not None:
                request["completed_at"] = time.monotonic()

            try:
                remaining = max(0.1, collection_deadline - time.monotonic())
                stdout, stderr = process.communicate(timeout=remaining)
                error_text = (stderr or "").lower()
                if process.returncode == 0:
                    outcome = "ACCEPTED"
                elif (
                    "failed calling webhook" in error_text
                    and "no endpoints available for service" in error_text
                    and "kyverno-svc" in error_text
                ):
                    outcome = "FAIL_CLOSED_WEBHOOK_UNAVAILABLE"
                else:
                    outcome = "REJECTED_OR_ERROR"
            except subprocess.TimeoutExpired:
                # Kill kubectl and any child processes in its dedicated group.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

                try:
                    stdout, stderr = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    stdout, stderr = process.communicate(timeout=3)

                require(
                    process.poll() is not None,
                    f"Admission request process group did not terminate: "
                    f"{request['name']}",
                )
                outcome = "CLIENT_TIMEOUT"

            completed_at = request["completed_at"]
            result["admission_requests_during_outage"].append({
                "name": request["name"],
                "returncode": process.returncode,
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "elapsed_seconds": round(
                    time.monotonic() - request["started_at"], 3
                ),
                "completed_before_restore": (
                    completed_at is not None
                    and restore_started is not None
                    and completed_at <= restore_started
                ),
                "completed_at_elapsed_seconds": (
                    round(completed_at - request["started_at"], 3)
                    if completed_at is not None else None
                ),
                "outcome": outcome,
            })


    # Time from confirmed endpoint loss until the original selector
    # restoration command completes. This is the measured fault-active period.
    result["selector_fault_duration_seconds"] = (
        round(restore_completed_at - outage_started, 3)
        if outage_started is not None and restore_completed_at is not None
        else None
    )

    # Kubernetes may need additional time to repopulate EndpointSlices.
    result["endpoint_recovery_seconds_after_restore"] = (
        round(recovery_completed_at - restore_completed_at, 3)
        if restore_completed_at is not None and recovery_completed_at is not None
        else None
    )

    # Total time the Service had no ready endpoints, including propagation.
    result["total_service_unavailable_duration_seconds"] = (
        round(recovery_completed_at - outage_started, 3)
        if outage_started is not None and recovery_completed_at is not None
        else None
    )

    result["fault_window_clock_to_restore_request_seconds"] = (
        round(restore_started - fault_window_started, 3)
        if fault_window_started is not None and restore_started is not None
        else None
    )
    result["completed_at_utc"] = timestamp()
    requests = result["admission_requests_during_outage"]
    result["experiment_success"] = (
        result["fault_injected"]
        and result["controller_pod_restart_requested"]
        and result["controller_recovered_ready"]
        and result["restore_command_succeeded"] is True
        and result.get("service_selector_restored_exactly") is True
        and result["service_endpoints_recovered"]
        and result.get("post_recovery_checks") == "PASS"
        and result.get("deadline_restore_verified") is True
        and result.get("deadline_restore_outcome") == "CANCELLED_BEFORE_DEADLINE"
        and result["watchdog_cancelled"]
        and (result.get("apiserver_endpoint_preflight") or {}).get("passed") is True
        and len(requests) == 5
        and all(
            item["outcome"] == "FAIL_CLOSED_WEBHOOK_UNAVAILABLE"
            and item["completed_before_restore"] is True
            for item in requests
        )
        and result.get("selector_fault_duration_seconds") is not None
        and result["selector_fault_duration_seconds"] <= FAULT_SECONDS
        and not result["errors"]
    )

    output = save_result(result)
    print("\n========== KYVERNO EXPERIMENT RESULT ==========")
    print(json.dumps(result, indent=2))
    print(f"\nResult saved: {output}")
    return 0 if result["experiment_success"] else 1


if __name__ == "__main__":
    sys.exit(main())
