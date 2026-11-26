#!/usr/bin/env python3
"""Native eventTime -> independently verified quarantine (LocalStack only).

Attack: a disposable IAM user disables KMS key rotation with its own access key.
t_event is the CloudTrail eventTime carried by the real event.
t_verified is taken after this script's own IAM read-back confirms the controls.
"""
import argparse, hashlib, json, math, os, signal, statistics, subprocess, sys
import tempfile, time, urllib.request, uuid, threading
from datetime import datetime, timezone
from pathlib import Path
import boto3
from botocore.config import Config

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = os.environ.get("CCPD_LOCALSTACK_ENDPOINT", "http://127.0.0.1:4566")
REGION = "eu-north-1"


def client(service, ak="test", sk="test", config=None):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name=REGION,
                        aws_access_key_id=ak, aws_secret_access_key=sk,
                        config=config)


def attach_timing_hooks(client_obj, service, operation, label, records, lock):
    """Capture botocore before-call/after-call duration for one API operation."""
    def before_call(model, params, context, **kwargs):
        context["ccpd_benchmark_started"] = time.monotonic()

    def after_call(http_response, parsed, model, context, **kwargs):
        started = context.pop("ccpd_benchmark_started", None)
        if started is None:
            return

        error = parsed.get("Error", {}) if isinstance(parsed, dict) else {}
        record = {
            "client": label,
            "service": service,
            "operation": operation,
            "duration_seconds": round(time.monotonic() - started, 6),
            "http_status": getattr(http_response, "status_code", None),
            "error_code": error.get("Code") if isinstance(error, dict) else None,
        }
        with lock:
            records.append(record)

    client_obj.meta.events.register(
        f"before-call.{service}.{operation}", before_call
    )
    client_obj.meta.events.register(
        f"after-call.{service}.{operation}", after_call
    )


def sh(*cmd):
    return subprocess.check_output(cmd, cwd=ROOT, text=True).strip()


def file_sha(rel):
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()[:12]


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def find_action(log, arn):
    if not log.exists():
        return None
    for line in log.read_text().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("target") == arn:
            return rec
    return None


def write_identity_map(path, identities):
    """Atomically write the benchmark-only LocalStack identity map."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = json.dumps(
        {"version": 1, "identities": identities},
        sort_keys=True,
        indent=2,
    ) + "\n"

    fd, temporary = tempfile.mkstemp(
        prefix=".identity-map-",
        dir=str(path.parent),
        text=True,
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def find_alert_record(alert_path, event_id):
    if not event_id or not alert_path.exists():
        return None
    for line in alert_path.read_text(encoding="utf-8").splitlines():
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        if alert.get("event_id") == event_id:
            return alert
    return None


def readback(iam, user, deny, sess):
    inline = iam.list_user_policies(UserName=user)["PolicyNames"]
    attached = [p["PolicyName"] for p in
                iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]]
    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    return {
        "deny_policy": deny in inline or deny in attached,
        "session_policy": sess in inline or sess in attached,
        "keys_inactive": bool(keys) and all(k["Status"] == "Inactive" for k in keys),
    }


def pct(values, p):
    s = sorted(values)
    return s[max(0, math.ceil(p * len(s)) - 1)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--observation-window", type=float, default=15)
    ap.add_argument("--label", default="native")
    ap.add_argument("--out-dir", default="evidence/results/native-eventtime")
    a = ap.parse_args()
    if a.observation_window <= 0:
        ap.error("--observation-window must be greater than zero")

    cfg = json.load(open(ROOT / "config/soar.json"))
    deny = cfg.get("deny_policy_name", "CCPDQuarantineDenyAll")
    sess = cfg.get("session_revocation_policy_name", "AWSRevokeOlderSessions")
    account = cfg["expected_account_id"]

    others = subprocess.run(["pgrep", "-af", "sqs_consumer|auto_soar_watcher"],
                            capture_output=True, text=True).stdout.strip()
    if others:
        sys.exit("REFUSED: other consumers/watchers would steal queue messages:\n" + others)

    iam, kms, sqs = client("iam"), client("kms"), client("sqs")
    raw_queue = os.environ.get("CCPD_NATIVE_EVENTTIME_INPUT_QUEUE_URL")
    queue = os.environ.get("CCPD_BENCHMARK_QUEUE_URL")
    if not raw_queue or not queue:
        sys.exit(
            "REFUSED: set CCPD_NATIVE_EVENTTIME_INPUT_QUEUE_URL to the "
            "dedicated raw CloudTrail queue and CCPD_BENCHMARK_QUEUE_URL "
            "to the dedicated normalized-alert queue."
        )
    if raw_queue == queue:
        sys.exit("REFUSED: raw input and normalized-alert queues must differ.")

    # Never purge queues. Both isolated queues must be empty before a run.
    for queue_name, queue_url in (
        ("raw CloudTrail input", raw_queue),
        ("normalized SOAR alerts", queue),
    ):
        queue_state = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
            ],
        )["Attributes"]
        visible = int(queue_state.get("ApproximateNumberOfMessages", "0"))
        in_flight = int(
            queue_state.get("ApproximateNumberOfMessagesNotVisible", "0")
        )
        if visible or in_flight:
            sys.exit(
                f"REFUSED: {queue_name} queue is not empty "
                f"(visible={visible}, in_flight={in_flight}). "
                "No messages were deleted."
            )

    time.sleep(2)

    work = Path(tempfile.mkdtemp(prefix="ccpd-native-"))
    log = work / "log.jsonl"
    identity_map_path = work / "localstack-identity-map.json"
    identity_map = {}
    write_identity_map(identity_map_path, identity_map)

    consumer_env = os.environ.copy()
    consumer_env["CCPD_LOCALSTACK_IDENTITY_MAP_PATH"] = str(
        identity_map_path
    )

    consumer = None
    watcher = None
    try:
        consumer = subprocess.Popen(
            [
                sys.executable, "-m", "detector.sqs_consumer",
                "--queue-url", raw_queue,
                "--alert-queue-url", queue,
                "--state-path", str(work / "detector-state.json"),
                "--alert-path", str(work / "detector-alerts.jsonl"),
            ],
            cwd=ROOT,
            env=consumer_env,
            stdout=open(work / "consumer.out", "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        time.sleep(2)
        if consumer.poll() is not None:
            raise RuntimeError(
                f"Detector consumer exited during startup "
                f"(exit={consumer.returncode}); inspect {work / 'consumer.out'}"
            )

        watcher = subprocess.Popen(
            [
                sys.executable, "scripts/auto_soar_watcher.py",
                "--queue-url", queue,
                "--no-consumer",
                "--config", "config/soar.json",
                "--alerts", str(work / "detector-alerts.jsonl"),
                "--state", str(work / "state.json"),
                "--checkpoint", str(work / "watcher-checkpoint.json"),
                "--log", str(log),
                "--duration", str(int(a.runs * (a.timeout + 10) + 30)),
                "--execute",
            ],
            cwd=ROOT,
            stdout=open(work / "watcher.out", "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        time.sleep(3)
        if watcher.poll() is not None:
            raise RuntimeError(
                f"SOAR watcher exited during startup "
                f"(exit={watcher.returncode}); inspect {work / 'watcher.out'}"
            )
        print(f"DETECTOR_CONSUMER_READY pid={consumer.pid}", flush=True)
        print(f"SOAR_WATCHER_READY pid={watcher.pid}", flush=True)
    except Exception:
        for proc in (watcher, consumer):
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
        raise

    runs, created = [], []
    unsafe_cleanup_users = set()
    try:
        for n in range(1, a.runs + 1):
            user = "ccpd-nat-" + uuid.uuid4().hex[:10]
            arn = f"arn:aws:iam::{account}:user/{user}"
            key_id = kms.create_key(Description="ccpd-native-bench")["KeyMetadata"]["KeyId"]
            kms.enable_key_rotation(KeyId=key_id)
            created_user = iam.create_user(UserName=user)["User"]
            user_id = created_user["UserId"]

            identity_map[arn] = {
                "account_id": account,
                "user_id": user_id,
            }
            write_identity_map(identity_map_path, identity_map)

            iam.put_user_policy(UserName=user, PolicyName="attack", PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow",
                               "Action": ["kms:DisableKeyRotation", "kms:DescribeKey"],
                               "Resource": "*"}]}))
            ak = iam.create_access_key(UserName=user)["AccessKey"]
            created.append((user, key_id))
            bounded_config = Config(
                connect_timeout=2, read_timeout=5,
                retries={"total_max_attempts": 1},
            )
            attacker = client(
                "kms", ak["AccessKeyId"], ak["SecretAccessKey"],
                config=bounded_config,
            )
            # STS is used only for the initial credential-authentication check.
            credential_probe = client(
                "sts", ak["AccessKeyId"], ak["SecretAccessKey"],
                config=bounded_config,
            )

            # This operation is explicitly allowed before the attack.
            # It tests authorization after the responder quarantines the user.
            authorization_probe = client(
                "kms", ak["AccessKeyId"], ak["SecretAccessKey"],
                config=bounded_config,
            )

            api_timings = []
            timing_lock = threading.Lock()
            attach_timing_hooks(
                attacker, "kms", "DisableKeyRotation",
                "attacker", api_timings, timing_lock,
            )
            attach_timing_hooks(
                authorization_probe, "kms", "DescribeKey",
                "authorization_probe", api_timings, timing_lock,
            )
            attach_timing_hooks(
                credential_probe, "sts", "GetCallerIdentity",
                "credential_probe", api_timings, timing_lock,
            )

            time.sleep(1)  # identity settles; not counted

            # Both baseline checks must succeed before the attack.
            credential_probe.get_caller_identity()
            authorization_probe.describe_key(KeyId=key_id)

            attack_state = {}

            def perform_attack():
                try:
                    attacker.disable_key_rotation(KeyId=key_id)
                    attack_state["result"] = "SUCCESS"
                except Exception as exc:
                    response = getattr(exc, "response", {})
                    error = response.get("Error", {}) if isinstance(response, dict) else {}
                    attack_state["result"] = "ERROR"
                    attack_state["error_type"] = type(exc).__name__
                    attack_state["error_code"] = error.get("Code")
                    attack_state["error"] = str(exc)
                finally:
                    attack_state["finished_wall"] = time.time()
                    attack_state["finished_mono"] = time.monotonic()

            # Start the attack asynchronously so the independent credential
            # probe can run while the attack API request is in flight.
            t_call = time.time()
            t_call_mono = time.monotonic()
            attack_thread = threading.Thread(target=perform_attack, daemon=True)
            attack_thread.start()

            action = None
            action_observed_mono = None
            quarantine_readback = None
            quarantine_verified_wall = None
            deadline = t_call_mono + a.timeout
            next_authorization_probe = t_call_mono
            next_credential_probe = None

            probe_samples = 0
            probe_successes = 0
            credential_probe_samples = 0
            credential_probe_successes = 0

            authorization_denied = False
            authorization_denial_code = None
            authorization_denial_type = None
            authorization_denial_wall = None

            credential_authentication_denied = False
            credential_authentication_denial_code = None
            credential_authentication_denial_type = None
            credential_authentication_denial_wall = None

            authorization_probe_error = None
            credential_authentication_probe_error = None
            watcher_exit_observed = None

            authorization_denial_codes = {
                "AccessDenied",
                "AccessDeniedException",
                "UnauthorizedOperation",
            }
            authentication_denial_codes = {
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
                "UnrecognizedClientException",
            }

            while time.monotonic() < deadline:
                now = time.monotonic()

                # Independently test KMS authorization approximately every
                # 100ms until a recognized authorization denial is observed.
                if not authorization_denied and now >= next_authorization_probe:
                    probe_samples += 1
                    try:
                        authorization_probe.describe_key(KeyId=key_id)
                        probe_successes += 1
                    except Exception as exc:
                        response = getattr(exc, "response", {})
                        error = response.get("Error", {}) if isinstance(response, dict) else {}
                        code = error.get("Code") if isinstance(error, dict) else None

                        if code in authorization_denial_codes:
                            authorization_denied = True
                            authorization_denial_code = code
                            authorization_denial_type = type(exc).__name__
                            authorization_denial_wall = time.time()
                        else:
                            authorization_probe_error = {
                                "type": type(exc).__name__,
                                "code": code,
                                "message": str(exc),
                            }

                    next_authorization_probe = time.monotonic() + 0.1

                found_action = find_action(log, arn)
                if found_action is not None and action is None:
                    action = found_action
                    action_observed_mono = time.monotonic()
                    next_credential_probe = action_observed_mono

                    if action.get("status") == "QUARANTINE_VERIFIED":
                        quarantine_readback = readback(iam, user, deny, sess)
                        quarantine_verified_wall = time.time()

                # Independently test whether the attacker's credentials still
                # authenticate to STS. A KMS denial does not stop this probe.
                if (
                    action_observed_mono is not None
                    and not credential_authentication_denied
                    and next_credential_probe is not None
                    and now >= next_credential_probe
                ):
                    credential_probe_samples += 1
                    try:
                        credential_probe.get_caller_identity()
                        credential_probe_successes += 1
                    except Exception as exc:
                        response = getattr(exc, "response", {})
                        error = response.get("Error", {}) if isinstance(response, dict) else {}
                        code = error.get("Code") if isinstance(error, dict) else None

                        if code in authentication_denial_codes:
                            credential_authentication_denied = True
                            credential_authentication_denial_code = code
                            credential_authentication_denial_type = type(exc).__name__
                            credential_authentication_denial_wall = time.time()
                        else:
                            credential_authentication_probe_error = {
                                "type": type(exc).__name__,
                                "code": code,
                                "message": str(exc),
                            }

                    next_credential_probe = time.monotonic() + 0.1

                # Do not stop after only one type of denial. Wait for both
                # independent denials or the configured observation window.
                if action_observed_mono is not None:
                    both_denials_observed = (
                        authorization_denied
                        and credential_authentication_denied
                    )
                    observation_complete = (
                        time.monotonic()
                        >= action_observed_mono + a.observation_window
                    )
                    if both_denials_observed or observation_complete:
                        break

                watcher_exit_code = watcher.poll()
                if watcher_exit_code is not None:
                    watcher_exit_observed = watcher_exit_code

                time.sleep(0.005)

            # Wait for the bounded attack request before disposable-user cleanup.
            attack_thread.join(timeout=10)
            attack_thread_alive = attack_thread.is_alive()
            if attack_thread_alive:
                # Never delete credentials/resources while their API call
                # may still be in flight. Preserve this user's resources.
                unsafe_cleanup_users.add(user)
            t_call_end = attack_state.get("finished_wall")

            rec = {
                "run": n,
                "user": user,
                "user_arn": arn,
                "iam_user_id": user_id,
                "localstack_identity_compatibility_enabled": True,
                "t_call": t_call,
                "t_call_end": t_call_end,
                "attack_call_result": attack_state.get("result"),
                "attack_call_error_type": attack_state.get("error_type"),
                "attack_call_error_code": attack_state.get("error_code"),
                "attack_thread_still_running_after_join": attack_thread_alive,
                "authorization_denied": authorization_denied,
                "authorization_denial_code": authorization_denial_code,
                "authorization_denial_type": authorization_denial_type,
                "t_authorization_denied": authorization_denial_wall,
                "authorization_denial_seconds": (
                    round(authorization_denial_wall - t_call, 6)
                    if authorization_denial_wall is not None else None
                ),
                "credential_authentication_denied": credential_authentication_denied,
                "credential_authentication_denial_code": credential_authentication_denial_code,
                "credential_authentication_denial_type": credential_authentication_denial_type,
                "t_credential_authentication_denied": credential_authentication_denial_wall,
                "credential_authentication_denial_seconds": (
                    round(credential_authentication_denial_wall - t_call, 6)
                    if credential_authentication_denial_wall is not None else None
                ),
                "credential_authentication_probe_operation": "sts:GetCallerIdentity",
                "credential_authentication_probe_baseline": "SUCCESS",
                "credential_authentication_probe_interval_seconds": 0.1,
                "credential_authentication_probe_samples": credential_probe_samples,
                "credential_authentication_probe_successes": credential_probe_successes,
                "credential_authentication_probe_other_error": credential_authentication_probe_error,
                "post_action_observation_window_s": a.observation_window,
                "authorization_probe_operation": "kms:DescribeKey",
                "authorization_probe_baseline": "SUCCESS",
                "authorization_probe_interval_seconds": 0.1,
                "authorization_probe_samples": probe_samples,
                "authorization_probe_successes": probe_successes,
                "authorization_probe_other_error": authorization_probe_error,
                "watcher_exit_code_during_observation": watcher_exit_observed,
                "watcher_failed": watcher_exit_observed is not None,
                "botocore_api_timings": list(api_timings),
                "status": (action or {}).get("status"),
                "timed_out": action is None,
                "infrastructure_error": (
                    "watcher_exited_before_action"
                    if watcher_exit_observed is not None and action is None
                    else None
                ),
            }
            if action:
                alert_record = find_alert_record(
                    work / "detector-alerts.jsonl",
                    action.get("event_id"),
                )

                if not isinstance(alert_record, dict):
                    raise RuntimeError(
                        "Identity validation failed: matching detector alert "
                        f"is missing for event {action.get('event_id')!r}"
                    )

                identity_evidence = alert_record.get("identity_normalization")

                if (
                    alert_record.get("caller_arn") != rec.get("user_arn")
                    or alert_record.get("caller_type_reported") != "IAMUser"
                    or alert_record.get("caller_principal_id")
                        != rec.get("iam_user_id")
                ):
                    raise RuntimeError(
                        "Identity validation failed: alert caller ARN, type, "
                        "or principal ID does not match the disposable IAM "
                        f"user for event {action.get('event_id')!r}"
                    )

                if identity_evidence is not None:
                    if (
                        not isinstance(identity_evidence, dict)
                        or identity_evidence.get("adapter")
                            != "localstack-identity-compat-v1"
                        or identity_evidence.get("source") != "LocalStack-only"
                        or identity_evidence.get("reported_type")
                            not in {"Root", "IAMUser"}
                        or identity_evidence.get("reported_principal_id")
                            != account
                        or identity_evidence.get("normalized_type") != "IAMUser"
                        or identity_evidence.get("normalized_principal_id")
                            != rec.get("iam_user_id")
                        or identity_evidence.get("matched_iam_user_arn")
                            != rec.get("user_arn")
                    ):
                        raise RuntimeError(
                            "Identity validation failed: LocalStack "
                            "compatibility evidence is invalid for event "
                            f"{action.get('event_id')!r}"
                        )
                    rec["identity_validation_mode"] = "localstack-compatibility"
                    rec["identity_normalization_evidence"] = identity_evidence
                else:
                    rec["identity_validation_mode"] = "native-cloudtrail-identity"
                t_event = ts(action["alert_event_time"])
                rec.update({
                    "t_event": t_event,
                    "t_watcher_seen": ts(action["watcher_seen_utc"]),
                    "t_logged": ts(action["logged_utc"]),
                    "responder_event_to_verified_s": action.get("event_to_verified_seconds"),
                    "responder_execution_s": action.get("execution_duration_seconds"),
                    "event_time_inside_call_window": (
                        t_call - 1 <= t_event <=
                        (t_call_end if t_call_end is not None else t_call + a.timeout) + 1
                    )})
                if action.get("status") == "QUARANTINE_VERIFIED":
                    rb = quarantine_readback or {}
                    t_verified = quarantine_verified_wall
                    rec["readback"] = rb
                    if t_verified is not None and all(rb.values()):
                        rec.update({
                            "t_verified": t_verified,
                            "event_to_verified_s": round(t_verified - t_event, 3),
                            "event_to_logged_s": round(rec["t_logged"] - t_event, 3),
                            "call_to_verified_s": round(t_verified - t_call, 3)})
            runs.append(rec)
            print(f"run {n:2d} status={rec['status']} "
                  f"event_to_verified={rec.get('event_to_verified_s')} "
                  f"call_to_verified={rec.get('call_to_verified_s')} "
                  f"in_window={rec.get('event_time_inside_call_window')}", flush=True)
    finally:
        # Stop the watcher first, then the detector consumer. Neither
        # process is allowed to outlive this benchmark invocation.
        for proc in (watcher, consumer):
            if proc is None:
                continue
            try:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                except Exception:
                    pass

        for user, key_id in created:
            if user in unsafe_cleanup_users:
                print(
                    f"WARNING: skipped cleanup for {user}; "
                    "attack thread was still running.",
                    file=sys.stderr,
                    flush=True,
                )
                continue
            for fn in (
                lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                         for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
                lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                         for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
                lambda: iam.delete_user(UserName=user),
                lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)):
                try:
                    fn()
                except Exception:
                    pass

    good = [r["event_to_verified_s"] for r in runs if "event_to_verified_s" in r]
    info = {}
    try:
        info = json.load(urllib.request.urlopen(ENDPOINT + "/_localstack/info", timeout=5))
    except Exception:
        pass
    sha = sh("git", "rev-parse", "HEAD")
    modified = sh("git", "diff", "--name-only", "HEAD", "--",
                  "scripts", "soar", "detector", "config").split()
    compose = (ROOT / "docker-compose.yml").read_text()
    out = {
        "metric": "CloudTrail eventTime to independently verified quarantine",
        "attack": "kms:DisableKeyRotation by disposable IAM user",
        "attacker_key_probe": (
            "Independent attacker-credential probes. KMS DescribeKey tests "
            "authorization approximately every 100ms from attack time until "
            "a recognized authorization denial. STS GetCallerIdentity tests "
            "credential authentication approximately every 100ms from action "
            "discovery until a recognized authentication denial. Neither "
            "probe stops merely because the other observes a denial. "
            "Observation ends when both denials are observed, the configured "
            "post-action observation window expires, or the overall timeout "
            "is reached. Outcomes and timestamps are recorded separately."
        ),
        "post_action_observation_window_s": a.observation_window,
        "cleanup_skipped_users": sorted(unsafe_cleanup_users),
        "endpoint": ENDPOINT,
        "git_sha": sha, "modified_tracked_files": modified,
        "file_sha256_12": {f: file_sha(f) for f in (
            "scripts/auto_soar_watcher.py", "soar/cloud_soar_responder.py",
            "detector/sqs_consumer.py", "scripts/benchmark_native_eventtime.py")},
        "watcher_poll_interval_s": 0.05,
        "localstack": {k: info.get(k) for k in ("version", "edition")},
        "persistence_in_compose": 'PERSISTENCE: "1"' in compose,
        "loadavg_at_end": os.getloadavg(),
        "started_utc": datetime.fromtimestamp(runs[0]["t_call"], timezone.utc).isoformat() if runs else None,
        "runs": runs,
        "summary": {
            "runs": len(runs), "verified": len(good), "timed_out": sum(r["timed_out"] for r in runs),
            "watcher_failures": sum(bool(r.get("watcher_failed")) for r in runs),
            "infrastructure_errors": sum(
                bool(r.get("infrastructure_error")) for r in runs
            ),
            "under_1s": sum(v < 1 for v in good),
            "under_1s_of_total": f"{sum(v < 1 for v in good)}/{len(runs)}",
            "authorization_denied": sum(
                bool(r.get("authorization_denied")) for r in runs
            ),
            "authorization_denied_of_total": (
                f"{sum(bool(r.get('authorization_denied')) for r in runs)}/{len(runs)}"
            ),
            "authorization_denial_mean_s": (
                statistics.mean([
                    r["authorization_denial_seconds"] for r in runs
                    if r.get("authorization_denial_seconds") is not None
                ]) if any(r.get("authorization_denial_seconds") is not None
                          for r in runs) else None
            ),
            "authorization_denial_max_s": (
                max([
                    r["authorization_denial_seconds"] for r in runs
                    if r.get("authorization_denial_seconds") is not None
                ]) if any(r.get("authorization_denial_seconds") is not None
                          for r in runs) else None
            ),
            "credential_authentication_denied": sum(
                bool(r.get("credential_authentication_denied")) for r in runs
            ),
            "credential_authentication_denied_of_total": (
                f"{sum(bool(r.get('credential_authentication_denied')) for r in runs)}/{len(runs)}"
            ),
            "verified_of_total": f"{len(good)}/{len(runs)}",
            "attack_call_over_5s": sum(
                (r["t_call_end"] - r["t_call"]) > 5
                for r in runs
                if r.get("t_call_end") is not None
            ),
            "median_s": statistics.median(good) if good else None,
            "p90_s": pct(good, 0.9) if good else None,
            "max_s": max(good) if good else None}}
    d = ROOT / a.out_dir
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = d / f"{sha[:7]}{'-dirty' if modified else ''}-{a.label}-{stamp}.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out["summary"], indent=2))
    print("written:", path)


if __name__ == "__main__":
    main()
