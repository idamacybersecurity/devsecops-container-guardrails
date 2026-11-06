#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

import yaml

CONFIG = Path(__file__).resolve().parents[1] / "config" / "safety.yaml"

EXECUTION_ENABLED = {
    "kyverno": False,
    "telemetry": False,
    "tetragon": False,
}


def validate_request(experiment, namespace, duration, execute_requested=False):
    if not CONFIG.is_file():
        raise PermissionError("BLOCKED: safety configuration not found.")

    config = yaml.safe_load(CONFIG.read_text()) or {}
    scope = config.get("scope", {})
    limits = config.get("limits", {})

    allowed = scope.get("allowed_workload_namespaces", [])
    protected = scope.get("protected_namespaces", [])
    targets = scope.get("experiment_targets", {})

    duration_limits = {
        "kyverno": limits.get("kyverno_webhook_fault_seconds"),
        "telemetry": limits.get("telemetry_fault_seconds"),
        "tetragon": limits.get("tetragon_agent_recovery_timeout_seconds"),
    }

    if experiment not in EXECUTION_ENABLED:
        raise PermissionError("BLOCKED: unknown experiment.")

    if not isinstance(duration, int) or isinstance(duration, bool):
        raise PermissionError("BLOCKED: duration must be an integer.")

    maximum = duration_limits.get(experiment)
    if not isinstance(maximum, int) or maximum < 1:
        raise PermissionError("BLOCKED: invalid duration limit in configuration.")

    if duration < 1 or duration > maximum:
        raise PermissionError(
            f"BLOCKED: duration must be between 1 and {maximum} seconds."
        )

    expected_target = targets.get(experiment)

    if expected_target:
        if namespace != expected_target:
            raise PermissionError(
                f"BLOCKED: {experiment} must target {expected_target}."
            )
    elif namespace not in allowed:
        raise PermissionError("BLOCKED: namespace is not on the workload allowlist.")

    if namespace in protected and namespace != expected_target:
        raise PermissionError(
            f"BLOCKED: {namespace} is a protected namespace."
        )

    if execute_requested and not EXECUTION_ENABLED[experiment]:
        raise PermissionError(
            "BLOCKED: execution is disabled pending implementation "
            "and rollback review."
        )

    return {
        "experiment": experiment,
        "namespace": namespace,
        "duration_seconds": duration,
        "execution_requested": execute_requested,
        "execution_enabled": EXECUTION_ENABLED[experiment],
        "validation": "PASSED",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate chaos experiment safety conditions."
    )
    parser.add_argument(
        "--experiment",
        required=True,
        choices=["kyverno", "telemetry", "tetragon"],
    )
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    print("========== CHAOS SAFETY GUARD ==========")

    try:
        evidence = validate_request(
            args.experiment,
            args.namespace,
            args.duration,
            args.execute,
        )
    except (PermissionError, OSError, yaml.YAMLError) as exc:
        sys.exit(str(exc))

    print(f"Experiment: {evidence['experiment']}")
    print(f"Namespace:  {evidence['namespace']}")
    print(f"Duration:   {evidence['duration_seconds']}s")
    print("PASS: experiment target and safety checks")

    if args.execute:
        print("Execution request accepted by validation.")
    else:
        print("DRY RUN: no Kubernetes resources were changed.")


if __name__ == "__main__":
    main()
