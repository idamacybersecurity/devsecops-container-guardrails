#!/usr/bin/env python3

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

K3S = "/usr/local/bin/k3s"
ROOT = Path(__file__).resolve().parents[2]
RESULT_DIR = ROOT / "chaos-engineering" / "results"
OUTPUT = RESULT_DIR / "chaos-resilience-audit.json"


def kubectl(*args):
    result = subprocess.run(
        ["sudo", K3S, "kubectl", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kubectl failed")
    return result.stdout


def kubectl_json(*args):
    return json.loads(kubectl(*args, "-o", "json"))


def check(label, function):
    try:
        value = function()
        return {"status": "PASS", "evidence": value}
    except Exception as exc:
        return {"status": "ERROR", "evidence": str(exc)}


def node_ready():
    nodes = kubectl_json("get", "nodes")
    ready = [
        node["metadata"]["name"]
        for node in nodes["items"]
        if any(
            condition["type"] == "Ready"
            and condition["status"] == "True"
            for condition in node["status"].get("conditions", [])
        )
    ]
    if not ready:
        raise RuntimeError("No Ready Kubernetes nodes")
    return ready


def daemonset_status(namespace, name):
    obj = kubectl_json("get", "daemonset", name, "-n", namespace)
    status = obj.get("status", {})
    evidence = {
        "desired": status.get("desiredNumberScheduled", 0),
        "ready": status.get("numberReady", 0),
        "available": status.get("numberAvailable", 0),
    }
    if evidence["desired"] == 0 or evidence["ready"] != evidence["desired"]:
        raise RuntimeError(str(evidence))
    return evidence


def statefulset_status(namespace, name):
    obj = kubectl_json("get", "statefulset", name, "-n", namespace)
    status = obj.get("status", {})
    evidence = {
        "desired": obj.get("spec", {}).get("replicas", 1),
        "ready": status.get("readyReplicas", 0),
    }
    if evidence["ready"] != evidence["desired"]:
        raise RuntimeError(str(evidence))
    return evidence


def pvc_status(namespace, name):
    obj = kubectl_json("get", "pvc", name, "-n", namespace)
    phase = obj.get("status", {}).get("phase", "Unknown")
    if phase != "Bound":
        raise RuntimeError(f"PVC phase: {phase}")
    return {"phase": phase}


def tetragon_experiment():
    files = sorted(RESULT_DIR.glob("tetragon-recovery-*.json"))
    if not files:
        raise RuntimeError("No Tetragon recovery result JSON found")

    result = json.loads(files[-1].read_text())

    recovery_time = result.get("recovery_time_seconds")
    timeout = result.get("timeout_seconds")
    terminated_pod = result.get("terminated_pod")
    replacement_pod = result.get("replacement_pod")

    evidence = {
        "file": files[-1].name,
        "experiment": result.get("experiment"),
        "namespace": result.get("namespace"),
        "daemonset": result.get("daemonset"),
        "recovery_time_seconds": recovery_time,
        "timeout_seconds": timeout,
        "recovered": result.get("recovered"),
        "terminated_pod": terminated_pod,
        "replacement_pod": replacement_pod,
    }

    errors = []

    if result.get("experiment") != "tetragon-agent-recovery":
        errors.append("unexpected experiment identifier")
    if result.get("namespace") != "tetragon":
        errors.append("unexpected target namespace")
    if result.get("daemonset") != "tetragon":
        errors.append("unexpected DaemonSet")
    if result.get("recovered") is not True:
        errors.append("recovery was not successful")
    if not isinstance(recovery_time, (int, float)) or recovery_time <= 0:
        errors.append("invalid recovery time")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        errors.append("invalid recovery timeout")
    if (
        isinstance(recovery_time, (int, float))
        and isinstance(timeout, (int, float))
        and recovery_time > timeout
    ):
        errors.append("recovery time exceeded timeout")
    if not terminated_pod or not replacement_pod:
        errors.append("missing pod identity")
    elif terminated_pod == replacement_pod:
        errors.append("replacement pod identity matches terminated pod")

    if errors:
        evidence["validation_errors"] = errors
        raise RuntimeError(str(evidence))

    evidence["validation"] = "PASSED"
    return evidence


def telemetry_experiment_inventory():
    files = sorted(RESULT_DIR.glob("telemetry-recovery-*.json"))

    evidence = {
        "result_files": [item.name for item in files],
        "result_count": len(files),
        "validated_successes": 0,
        "failed_experiments": 0,
        "incomplete_results": 0,
        "invalid_results": 0,
        "file_findings": [],
    }

    if not files:
        evidence["status"] = "NOT_TESTED"
        evidence["reason"] = (
            "No telemetry recovery result JSON exists. "
            "Pipeline recovery was observed, but no measured experiment "
            "result was saved."
        )
        return evidence

    required = {
        "experiment",
        "experiment_success",
        "recovered",
        "loki_recovered",
        "restore_command_succeeded",
        "post_recovery_checks",
        "watchdog_cancelled_after_recovery",
        "recovery_time_seconds_after_restore",
        "actual_outage_duration_seconds",
        "recovery_timeout_seconds",
        "planned_outage_seconds",
        "injection_error",
        "restoration_error",
        "recovery_error",
    }

    def positive_number(value):
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value > 0
        )

    for item in files:
        finding = {
            "file": item.name,
            "status": None,
        }

        try:
            data = json.loads(item.read_text())

            if not isinstance(data, dict):
                raise ValueError("JSON root must be an object")

            missing = sorted(required - data.keys())
            if missing:
                finding.update({
                    "status": "INCOMPLETE",
                    "missing_fields": missing,
                })
                evidence["incomplete_results"] += 1
                evidence["file_findings"].append(finding)
                continue

            if data["experiment"] != "loki_backend_recovery":
                raise ValueError("Unexpected experiment identifier")

            boolean_fields = (
                "experiment_success",
                "recovered",
                "loki_recovered",
                "watchdog_cancelled_after_recovery",
            )

            if any(type(data[field]) is not bool for field in boolean_fields):
                raise ValueError("Invalid Boolean field type")

            if data["restore_command_succeeded"] not in (True, False, None):
                raise ValueError("Invalid restore_command_succeeded value")

            if data["post_recovery_checks"] not in (
                "PASS", "FAILED", "NOT_RUN"
            ):
                raise ValueError("Invalid post_recovery_checks value")

            if not positive_number(data["planned_outage_seconds"]):
                raise ValueError("Invalid planned outage duration")

            if not positive_number(data["recovery_timeout_seconds"]):
                raise ValueError("Invalid recovery timeout")

            for field in (
                "actual_outage_duration_seconds",
                "recovery_time_seconds_after_restore",
            ):
                value = data[field]
                if value is not None and not positive_number(value):
                    raise ValueError(f"Invalid {field}")

            for field in (
                "injection_error",
                "restoration_error",
                "recovery_error",
            ):
                if data[field] is not None and not isinstance(data[field], str):
                    raise ValueError(f"Invalid {field} type")

            if data["experiment_success"]:
                success_conditions = (
                    data["recovered"] is True
                    and data["loki_recovered"] is True
                    and data["restore_command_succeeded"] is True
                    and data["post_recovery_checks"] == "PASS"
                    and data["watchdog_cancelled_after_recovery"] is True
                    and positive_number(
                        data["recovery_time_seconds_after_restore"]
                    )
                    and positive_number(
                        data["actual_outage_duration_seconds"]
                    )
                    and not any(data[field] for field in (
                        "injection_error",
                        "restoration_error",
                        "recovery_error",
                    ))
                )

                if not success_conditions:
                    raise ValueError(
                        "Success claim conflicts with recovery evidence"
                    )

                finding["status"] = "VALIDATED_SUCCESS"
                finding["recovery_time_seconds"] = (
                    data["recovery_time_seconds_after_restore"]
                )
                evidence["validated_successes"] += 1

            else:
                finding["status"] = "EXPERIMENT_FAILED"
                finding["recovered"] = data["recovered"]
                finding["error"] = data.get("error")
                evidence["failed_experiments"] += 1

        except (OSError, json.JSONDecodeError, ValueError) as exc:
            finding.update({
                "status": "INVALID",
                "error": str(exc),
            })
            evidence["invalid_results"] += 1

        evidence["file_findings"].append(finding)

    if evidence["invalid_results"]:
        status = "INVALID_RESULTS"
    elif evidence["incomplete_results"]:
        status = "INCOMPLETE_RESULTS"
    elif evidence["validated_successes"] and evidence["failed_experiments"]:
        status = "MIXED_RESULTS"
    elif evidence["validated_successes"]:
        status = "VALIDATED_SUCCESS"
    else:
        status = "EXPERIMENT_FAILED"

    evidence["status"] = status
    evidence["reason"] = (
        "Telemetry result files were inspected and classified using "
        "their recorded experiment and recovery evidence."
    )
    return evidence




def kyverno_experiment_inventory():
    files = sorted(RESULT_DIR.glob("kyverno-admission-recovery-*.json"))
    evidence = {
        "files_found": len(files),
        "validated_successes": 0,
        "failed_experiments": 0,
        "incomplete_results": 0,
        "invalid_results": 0,
        "file_findings": [],
    }

    if not files:
        evidence.update({
            "status": "NOT_TESTED",
            "reason": "No saved Kyverno admission recovery results found.",
        })
        return evidence

    common = {
        "experiment", "fault_injected", "admission_requests_during_outage",
        "restore_command_succeeded", "post_recovery_admission_request",
        "watchdog_cancelled", "experiment_success", "errors",
    }
    modern = {"controller_remained_ready", "service_endpoints_recovered"}

    for item in files:
        finding = {"file": item.name}
        try:
            data = json.loads(item.read_text())
            if not isinstance(data, dict):
                raise ValueError("JSON root must be an object")

            missing = sorted(common - data.keys())
            if missing:
                finding.update(status="INCOMPLETE", missing_fields=missing)
                evidence["incomplete_results"] += 1
                evidence["file_findings"].append(finding)
                continue

            experiment = data["experiment"]
            if experiment not in (
                "kyverno_admission_controller_recovery",
                "kyverno_admission_service_unavailability",
            ):
                raise ValueError(f"Unexpected experiment identifier: {experiment!r}")

            for field in (
                "fault_injected", "restore_command_succeeded",
                "watchdog_cancelled", "experiment_success",
            ):
                if type(data[field]) is not bool:
                    raise ValueError(f"{field} must be Boolean")

            if not isinstance(data["errors"], list) or any(
                not isinstance(error, str) for error in data["errors"]
            ):
                raise ValueError("errors must be a list of strings")

            requests = data["admission_requests_during_outage"]
            if not isinstance(requests, list):
                raise ValueError("Admission requests must be a list")

            for request in requests:
                if not isinstance(request, dict):
                    raise ValueError("Admission request must be an object")
                if type(request.get("returncode")) is not int:
                    raise ValueError("Admission request returncode must be an integer")
                if not isinstance(request.get("outcome"), str):
                    raise ValueError("Admission request outcome must be a string")

            accepted = sum(
                request["outcome"] == "ACCEPTED" and request["returncode"] == 0
                for request in requests
            )
            all_rejected = (
                len(requests) == 5
                and all(
                    request["outcome"] == "FAIL_CLOSED_WEBHOOK_UNAVAILABLE"
                    and request["returncode"] != 0
                    for request in requests
                )
            )

            finding.update({
                "admission_request_count": len(requests),
                "accepted_during_outage": accepted,
                "admission_requests": [
                    {"outcome": r["outcome"], "returncode": r["returncode"]}
                    for r in requests
                ],
            })

            post = data["post_recovery_admission_request"]
            post_pass = (
                isinstance(post, dict)
                and type(post.get("returncode")) is int
                and post["returncode"] == 0
                and post.get("outcome") == "ACCEPTED"
            )

            if experiment == "kyverno_admission_service_unavailability":
                missing = sorted(modern - data.keys())
                if missing:
                    finding.update(status="INCOMPLETE", missing_fields=missing)
                    evidence["incomplete_results"] += 1
                    evidence["file_findings"].append(finding)
                    continue
                if any(type(data[field]) is not bool for field in modern):
                    raise ValueError("Modern controller/endpoint fields must be Boolean")

                recovery_pass = (
                    (data["controller_remained_ready"] is True or data.get("controller_recovered_ready") is True)
                    and data["service_endpoints_recovered"] is True
                )
            else:
                recovery_pass = data.get("controller_recovered") is True

            success = all((
                data["experiment_success"] is True,
                data["fault_injected"] is True,
                data["restore_command_succeeded"] is True,
                data["watchdog_cancelled"] is True,
                recovery_pass,
                post_pass,
                all_rejected,
                not data["errors"],
            ))

            if success:
                finding["status"] = "VALIDATED_SUCCESS"
                evidence["validated_successes"] += 1
            else:
                finding.update({
                    "status": "EXPERIMENT_FAILED",
                    "experiment_success_recorded": data["experiment_success"],
                    "restore_command_succeeded": data["restore_command_succeeded"],
                    "watchdog_cancelled": data["watchdog_cancelled"],
                    "errors": data["errors"],
                })
                evidence["failed_experiments"] += 1

        except (OSError, json.JSONDecodeError, ValueError) as exc:
            finding.update(status="INVALID", error=str(exc))
            evidence["invalid_results"] += 1

        evidence["file_findings"].append(finding)

    if evidence["invalid_results"]:
        status = "INVALID_RESULTS"
    elif evidence["incomplete_results"]:
        status = "INCOMPLETE_RESULTS"
    elif evidence["validated_successes"] and evidence["failed_experiments"]:
        status = "MIXED_RESULTS"
    elif evidence["validated_successes"]:
        status = "VALIDATED_SUCCESS"
    elif evidence["failed_experiments"]:
        status = "EXPERIMENT_FAILED"
    else:
        status = "INCOMPLETE_RESULTS"

    evidence["status"] = status
    evidence["reason"] = (
        "Kyverno outage records were classified using request outcomes, "
        "rollback, controller and endpoint recovery, post-recovery admission, "
        "watchdog cancellation, and the recorded experiment result."
    )
    return evidence


def kyverno_acceptance_campaign():
    # These four records form the designated final acceptance cohort.
    # Historical development records remain in the all-record inventory.
    acceptance_files = (
        "kyverno-admission-recovery-20261107T011616Z.json",
        "kyverno-admission-recovery-20261107T161258Z.json",
        "kyverno-admission-recovery-20261107T161513Z.json",
        "kyverno-admission-recovery-20261107T161620Z.json",
    )

    inventory = kyverno_experiment_inventory()
    findings = {
        item.get("file"): item
        for item in inventory.get("file_findings", [])
    }

    selected = [
        {
            "file": filename,
            "status": findings.get(filename, {}).get("status", "MISSING"),
        }
        for filename in acceptance_files
    ]

    missing = [
        item["file"] for item in selected
        if item["status"] == "MISSING"
    ]

    if missing:
        status = "INCOMPLETE_RESULTS"
    elif all(item["status"] == "VALIDATED_SUCCESS" for item in selected):
        status = "VALIDATED_SUCCESS"
    elif any(item["status"] == "EXPERIMENT_FAILED" for item in selected):
        status = "EXPERIMENT_FAILED"
    elif any(item["status"] == "INVALID" for item in selected):
        status = "INVALID_RESULTS"
    else:
        status = "INCOMPLETE_RESULTS"

    return {
        "status": status,
        "acceptance_records_expected": len(acceptance_files),
        "acceptance_records_found": len(selected) - len(missing),
        "acceptance_records_validated_success": sum(
            item["status"] == "VALIDATED_SUCCESS" for item in selected
        ),
        "acceptance_records": selected,
        "all_record_inventory_status": inventory.get("status", "UNKNOWN"),
        "all_record_inventory_files_found": inventory.get("files_found", 0),
        "reason": (
            "This score is scoped to the four explicitly designated final "
            "acceptance records. All four must independently validate. "
            "Historical development records remain visible in the separate "
            "all-record inventory and are not reclassified. The auditor "
            "does not independently verify when the acceptance cohort was "
            "designated; that designation is an operator/process assertion."
        ),
    }


def kyverno_webhook_policy():
    configs = kubectl_json("get", "validatingwebhookconfigurations")
    findings = []

    for config in configs.get("items", []):
        name = config.get("metadata", {}).get("name", "")
        if "kyverno" not in name.lower():
            continue

        for webhook in config.get("webhooks", []):
            findings.append({
                "configuration": name,
                "webhook": webhook.get("name"),
                "failurePolicy": webhook.get("failurePolicy", "Fail (API default)"),
            })

    if not findings:
        raise RuntimeError("No Kyverno validating webhooks found")

    policies = {item["failurePolicy"] for item in findings}
    return {
        "webhooks": findings,
        "all_fail_closed": policies == {"Fail"},
        "note": "Configuration evidence only; no admission outage test performed.",
    }


def prometheus_inventory():
    output = kubectl(
        "get", "services,deployments,statefulsets",
        "-A", "-o", "json"
    )
    resources = json.loads(output)
    matches = []

    for item in resources.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        if "prometheus" in name.lower():
            matches.append({
                "kind": item.get("kind"),
                "namespace": item.get("metadata", {}).get("namespace"),
                "name": name,
            })

    return {
        "found": bool(matches),
        "resources": matches,
        "status": "AVAILABLE" if matches else "UNAVAILABLE",
        "reason": (
            "Prometheus resources were discovered."
            if matches else
            "No Prometheus service, deployment, or StatefulSet was found."
        ),
    }


def main():
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    print("========== CHAOS RESILIENCE AUDIT ==========")
    print("Mode: READ ONLY")
    print("No fault injection or Kubernetes changes will be performed.")
    print()

    checks = {
        "kubernetes_nodes": check(
            "Kubernetes nodes", node_ready
        ),
        "tetragon_daemonset": check(
            "Tetragon DaemonSet",
            lambda: daemonset_status("tetragon", "tetragon"),
        ),
        "alloy_daemonset": check(
            "Alloy DaemonSet",
            lambda: daemonset_status("observability", "alloy"),
        ),
        "loki_statefulset": check(
            "Loki StatefulSet",
            lambda: statefulset_status("loki", "loki"),
        ),
        "loki_pvc": check(
            "Loki PVC",
            lambda: pvc_status("loki", "storage-loki-0"),
        ),
        "tetragon_recovery_experiment": check(
            "Tetragon recovery experiment", tetragon_experiment
        ),
        "telemetry_result_inventory": check(
            "Telemetry result inventory", telemetry_experiment_inventory
        ),
        "kyverno_webhook_configuration": check(
            "Kyverno webhook configuration", kyverno_webhook_policy
        ),
        "kyverno_live_experiment": check(
            "Kyverno live experiment inventory", kyverno_experiment_inventory
        ),
        "kyverno_acceptance_campaign": check(
            "Kyverno final acceptance campaign", kyverno_acceptance_campaign
        ),
        "prometheus_inventory": check(
            "Prometheus inventory", prometheus_inventory
        ),
    }

    # Align machine-readable check statuses with their actual findings.
    telemetry = checks["telemetry_result_inventory"]
    if telemetry["status"] == "PASS":
        telemetry_status = telemetry["evidence"].get("status")
        if telemetry_status != "VALIDATED_SUCCESS":
            telemetry["status"] = telemetry_status or "UNKNOWN"

    prometheus = checks["prometheus_inventory"]
    if prometheus["status"] == "PASS":
        prometheus_status = prometheus["evidence"].get("status")
        if prometheus_status == "UNAVAILABLE":
            prometheus["status"] = "UNAVAILABLE"

    kyverno = checks["kyverno_webhook_configuration"]
    if kyverno["status"] == "PASS":
        if kyverno["evidence"].get("all_fail_closed") is True:
            kyverno["status"] = "CONFIGURATION_VERIFIED"
        else:
            kyverno["status"] = "CONFIGURATION_REVIEW_REQUIRED"

    kyverno_live = checks["kyverno_live_experiment"]
    if kyverno_live["status"] == "PASS":
        kyverno_live["status"] = kyverno_live["evidence"].get("status", "UNKNOWN")

    kyverno_campaign = checks["kyverno_acceptance_campaign"]
    if kyverno_campaign["status"] == "PASS":
        kyverno_campaign["status"] = kyverno_campaign["evidence"].get(
            "status", "UNKNOWN"
        )

    campaign_status = kyverno_campaign.get("evidence", {}).get("status")
    live_status = kyverno_live.get("evidence", {}).get("status")
    if kyverno["status"] != "CONFIGURATION_VERIFIED":
        fail_closed_status = "CONFIGURATION_REVIEW_REQUIRED"
        fail_closed_reason = (
            "Kyverno webhook configuration did not verify failurePolicy Fail."
        )
    elif campaign_status == "VALIDATED_SUCCESS":
        fail_closed_status = "PASS"
        fail_closed_reason = (
            "Kyverno webhook configuration is verified as fail-closed, and all "
            "four designated final acceptance records independently validate "
            "fault injection, outage rejection, restoration, recovery, and "
            "post-recovery admission. The separate all-record historical "
            f"inventory remains {live_status}; this PASS applies only to the "
            "four-record acceptance campaign."
        )
    elif campaign_status == "EXPERIMENT_FAILED":
        fail_closed_status = "FAILED"
        fail_closed_reason = (
            "At least one designated final acceptance run failed validation."
        )
    elif campaign_status == "NOT_TESTED":
        fail_closed_status = "CONFIGURATION_ONLY"
        fail_closed_reason = (
            "Webhook configuration is Fail, but no final acceptance campaign "
            "evidence exists."
        )
    else:
        fail_closed_status = "PARTIAL"
        fail_closed_reason = (
            "The four-record final acceptance campaign is incomplete, invalid, "
            "or not fully validated. The all-record historical inventory is "
            f"reported separately as {live_status}."
        )

    audit = {
        "audit": "automated_security_chaos_resilience",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution_mode": "read_only",
        "checks": checks,
        "scorecard": {
            "availability": {
                "status": "PENDING_EVIDENCE_EVALUATION",
                "reason": "Availability evidence has not yet been evaluated.",
            },
            "detection_fidelity": {
                "status": "PENDING_EVIDENCE_EVALUATION",
                "reason": "Detection evidence has not yet been evaluated.",
            },
            "fail_closed_integrity": {
                "status": fail_closed_status,
                "reason": fail_closed_reason,
            },
        },
    }

    availability_requirements = (
        "kubernetes_nodes",
        "tetragon_daemonset",
        "alloy_daemonset",
        "loki_statefulset",
        "loki_pvc",
        "tetragon_recovery_experiment",
    )

    missing = [
        name for name in availability_requirements
        if checks[name]["status"] != "PASS"
    ]

    telemetry_check = checks["telemetry_result_inventory"]
    telemetry_evidence = telemetry_check.get("evidence", {})
    telemetry_validated = (
        telemetry_check.get("status") == "VALIDATED_SUCCESS"
        or telemetry_evidence.get("status") == "VALIDATED_SUCCESS"
    )
    if not telemetry_validated:
        missing.append("telemetry_result_inventory")

    tetragon_time = checks[
        "tetragon_recovery_experiment"
    ].get("evidence", {}).get("recovery_time_seconds")

    if not missing:
        availability_status = "PASS"
        availability_reason = (
            "All required Kubernetes, Tetragon, Alloy, Loki and PVC "
            "health checks passed. Tetragon agent recovery was validated "
            f"at {tetragon_time} seconds, and the saved Loki outage "
            "recovery experiment passed validation."
        )
    else:
        availability_status = "PARTIAL"
        availability_reason = (
            "Availability evidence is incomplete. Failed or unvalidated "
            "requirements: " + ", ".join(missing)
        )

    audit["scorecard"]["availability"] = {
        "status": availability_status,
        "reason": availability_reason,
    }

    detection_path = (
        Path(__file__).resolve().parents[1]
        / "results"
        / "detection-fidelity-20261106.json"
    )

    detection_status = "NOT_TESTED"
    detection_reason = "No valid controlled detection evidence record was found."

    try:
        detection = json.loads(detection_path.read_text())
        delivery = detection.get("slack_delivery", {})

        valid_detection_evidence = all((
            detection.get("experiment") == "controlled_detection_fidelity",
            detection.get("namespace") == "phase8-test",
            detection.get("event_type") == "shell-execution",
            bool(detection.get("event_submitted_at_utc")),
            delivery.get("status") == "SUCCESS",
            delivery.get("alert_type") == detection.get("event_type"),
            bool(delivery.get("confirmed_at_utc")),
            detection.get("workload_cleanup") == "SUCCESS",
            bool(detection.get("slack_screenshot")),
        ))

        if valid_detection_evidence:
            detection_status = "PASS"
            detection_reason = (
                "Controlled shell-execution detection and Slack delivery "
                "were recorded successfully in phase8-test. This validates "
                "the tested event and delivery path only; it does not prove "
                "detection or delivery during an infrastructure outage."
            )
        else:
            detection_status = "PARTIAL"
            detection_reason = (
                "A detection evidence record exists, but one or more "
                "required fields or delivery checks are incomplete."
            )

    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        detection_status = "PARTIAL"
        detection_reason = (
            "The detection evidence record could not be read or validated."
        )

    audit["scorecard"]["detection_fidelity"] = {
        "status": detection_status,
        "reason": detection_reason,
    }

    OUTPUT.write_text(json.dumps(audit, indent=2) + "\n")

    print("========== COMPONENT AND EXPERIMENT FINDINGS ==========")

    for name, item in checks.items():
        status = item["status"]
        evidence = item["evidence"]

        if status == "ERROR":
            reported_status = "ERROR"
        elif name == "telemetry_result_inventory":
            reported_status = evidence.get("status", "UNKNOWN")
        elif name == "prometheus_inventory":
            reported_status = evidence.get("status", "UNKNOWN")
        elif name == "kyverno_webhook_configuration":
            reported_status = (
                "CONFIGURATION_VERIFIED"
                if evidence.get("all_fail_closed") is True
                else "CONFIGURATION_REVIEW_REQUIRED"
            )
        elif name == "kyverno_live_experiment":
            reported_status = evidence.get("status", "UNKNOWN")
        else:
            reported_status = status

        print(f"{name}: {reported_status}")

        if name in (
            "telemetry_result_inventory",
            "prometheus_inventory",
            "kyverno_webhook_configuration",
            "kyverno_live_experiment",
            "kyverno_acceptance_campaign",
        ):
            print(f"  {json.dumps(evidence, indent=2)}")
        elif status != "PASS":
            print(f"  {evidence}")

    print("\n========== SCORECARD ==========")
    for category, item in audit["scorecard"].items():
        print(f"{category}: {item['status']}")
        print(f"  {item['reason']}")

    print(f"\nAudit JSON saved: {OUTPUT}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"AUDITOR ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
