#!/usr/bin/env python3
"""Native eventTime -> independently verified quarantine (LocalStack only).

Attack: a disposable IAM user disables KMS key rotation with its own access key.
t_event is the CloudTrail eventTime carried by the real event.
t_verified is taken after this script's own IAM read-back confirms the controls.
"""
import argparse, hashlib, json, math, os, statistics, subprocess, sys
import tempfile, time, urllib.request, uuid
from datetime import datetime, timezone
from pathlib import Path
import boto3

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"


def client(service, ak="test", sk="test"):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name=REGION,
                        aws_access_key_id=ak, aws_secret_access_key=sk)


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
    ap.add_argument("--label", default="native")
    ap.add_argument("--out-dir", default="evidence/results/native-eventtime")
    a = ap.parse_args()

    cfg = json.load(open(ROOT / "config/soar.json"))
    deny = cfg.get("deny_policy_name", "CCPDQuarantineDenyAll")
    sess = cfg.get("session_revocation_policy_name", "AWSRevokeOlderSessions")
    account = cfg["expected_account_id"]

    iam, kms, sqs = client("iam"), client("kms"), client("sqs")
    queue = os.environ.get("SECURITY_EVENT_QUEUE_URL") or next(
        u for u in sqs.list_queues().get("QueueUrls", [])
        if "security" in u and "dlq" not in u)
    sqs.purge_queue(QueueUrl=queue)
    time.sleep(2)

    work = Path(tempfile.mkdtemp(prefix="ccpd-native-"))
    log = work / "log.jsonl"
    watcher = subprocess.Popen(
        [sys.executable, "scripts/auto_soar_watcher.py", "--queue-url", queue,
         "--config", "config/soar.json", "--alerts", str(work / "alerts.jsonl"),
         "--state", str(work / "state.json"), "--log", str(log),
         "--duration", str(int(a.runs * (a.timeout + 10) + 30)), "--execute"],
        cwd=ROOT, stdout=open(work / "watcher.out", "w"), stderr=subprocess.STDOUT)
    time.sleep(3)

    runs, created = [], []
    try:
        for n in range(1, a.runs + 1):
            user = "ccpd-nat-" + uuid.uuid4().hex[:10]
            arn = f"arn:aws:iam::{account}:user/{user}"
            key_id = kms.create_key(Description="ccpd-native-bench")["KeyMetadata"]["KeyId"]
            kms.enable_key_rotation(KeyId=key_id)
            iam.create_user(UserName=user)
            iam.put_user_policy(UserName=user, PolicyName="attack", PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["kms:DisableKeyRotation"],
                               "Resource": "*"}]}))
            ak = iam.create_access_key(UserName=user)["AccessKey"]
            created.append((user, key_id))
            attacker = client("kms", ak["AccessKeyId"], ak["SecretAccessKey"])
            time.sleep(1)  # identity settles; not counted

            t_call = time.time()
            attacker.disable_key_rotation(KeyId=key_id)
            t_call_end = time.time()

            action, deadline = None, t_call + a.timeout
            while time.time() < deadline:
                action = find_action(log, arn)
                if action or watcher.poll() is not None:
                    break
                time.sleep(0.01)

            rec = {"run": n, "user": user, "t_call": t_call, "t_call_end": t_call_end,
                   "status": (action or {}).get("status"), "timed_out": action is None}
            if action:
                t_event = ts(action["alert_event_time"])
                rec.update({
                    "t_event": t_event,
                    "t_watcher_seen": ts(action["watcher_seen_utc"]),
                    "t_logged": ts(action["logged_utc"]),
                    "responder_event_to_verified_s": action.get("event_to_verified_seconds"),
                    "responder_execution_s": action.get("execution_duration_seconds"),
                    "event_time_inside_call_window":
                        t_call - 1 <= t_event <= t_call_end + 1})
                if action.get("status") == "QUARANTINE_VERIFIED":
                    rb = readback(iam, user, deny, sess)
                    t_verified = time.time()
                    rec["readback"] = rb
                    if all(rb.values()):
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
        watcher.terminate()
        for user, key_id in created:
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
            "under_1s": sum(v < 1 for v in good),
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
