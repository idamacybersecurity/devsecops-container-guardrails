#!/usr/bin/env python3
"""Scenario 2 (defense evasion), quarantine only, autonomous (LocalStack only).

Attack steps only. No containment API is called here; the watcher must act.
Uses disposable KMS key and bucket, never the audit bucket.
"""
import json, os, signal, subprocess, sys, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
EP, R = "http://127.0.0.1:4566", "eu-north-1"
CFG = json.load(open(ROOT / "config/soar.json"))
ACC = CFG["expected_account_id"]
DENY = CFG.get("deny_policy_name", "CCPDQuarantineDenyAll")
SESS = CFG.get("session_revocation_policy_name", "AWSRevokeOlderSessions")


def c(svc, ak="test", sk="test"):
    return boto3.client(svc, endpoint_url=EP, region_name=R,
                        aws_access_key_id=ak, aws_secret_access_key=sk)


def sh(*cmd):
    return subprocess.check_output(cmd, cwd=ROOT, text=True).strip()


def ts(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()


def readback(iam, user):
    inline = set(iam.list_user_policies(UserName=user)["PolicyNames"])
    att = {p["PolicyName"] for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]}
    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    return {"deny_policy": DENY in inline | att, "session_policy": SESS in inline | att,
            "keys_inactive": bool(keys) and all(k["Status"] == "Inactive" for k in keys)}


def main():
    others = subprocess.run(["pgrep", "-af", "sqs_consumer|auto_soar_watcher"],
                            capture_output=True, text=True).stdout.strip()
    if others:
        sys.exit("REFUSED: consumer/watcher already running:\n" + others)
    iam, kms, s3, sqs = c("iam"), c("kms"), c("s3"), c("sqs")
    queue = os.environ.get("SECURITY_EVENT_QUEUE_URL")
    if not queue or "/ccpd-autonomous-test-" not in queue:
        sys.exit(
            "REFUSED: set SECURITY_EVENT_QUEUE_URL to an isolated "
            "ccpd-autonomous-test-* queue. Main security queues are prohibited."
        )
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue,
        AttributeNames=["QueueArn"],
    )["Attributes"]
    if "ccpd-autonomous-test-" not in attrs.get("QueueArn", ""):
        sys.exit("REFUSED: queue ARN is not an approved isolated test queue.")
    # Never purge: preserve queued evidence and prevent destructive fallback.
    time.sleep(2)

    tag = uuid.uuid4().hex[:8]
    bucket = f"ccpd-sc2-{tag}"
    key_id = kms.create_key(Description="ccpd-sc2-disposable")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": R})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACC}:root"},
         "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}))

    work = Path(tempfile.mkdtemp(prefix="ccpd-sc2-"))
    log = work / "log.jsonl"
    watcher_out = work / "watcher.out"
    watcher = subprocess.Popen(
        [sys.executable, "-u", "scripts/auto_soar_watcher.py",
         "--queue-url", queue, "--config", "config/soar.json",
         "--alerts", str(work / "alerts.jsonl"),
         "--state", str(work / "state.json"),
         "--log", str(log),
         "--checkpoint", str(work / "checkpoint.json"),
         "--duration", "300", "--execute"],
        cwd=ROOT, stdout=open(watcher_out, "w"),
        stderr=subprocess.STDOUT, start_new_session=True)

    # Do not launch attacks until this run's watcher is initialized.
    ready_deadline = time.time() + 15
    while time.time() < ready_deadline:
        if watcher.poll() is not None:
            raise RuntimeError(
                "watcher_exited_before_ready: " +
                watcher_out.read_text(errors="replace")
            )
        if watcher_out.exists() and "WATCHER_READY" in watcher_out.read_text(errors="replace"):
            break
        time.sleep(0.1)
    else:
        watcher.terminate()
        watcher.wait(timeout=10)
        raise RuntimeError(
            "watcher_ready_timeout: " +
            watcher_out.read_text(errors="replace")
        )

    res = {"scenario": "2 defense evasion (KMS rotation, S3 policy delete), quarantine only, autonomous",
           "operator_actions": [], "restoration": "NOT performed by this run (S3: drift reconciler; KMS: manual)",
           "git_sha": sh("git", "rev-parse", "HEAD"),
           "modified_tracked_files": sh("git", "diff", "--name-only", "HEAD", "--", "scripts", "soar", "detector", "config").split(),
           "attacks": []}
    users = []
    attacks = [
        ("kms:DisableKeyRotation", ["kms:DisableKeyRotation"], "*",
         lambda cl: cl["kms"].disable_key_rotation(KeyId=key_id)),
        ("s3:DeleteBucketPolicy", ["s3:DeleteBucketPolicy"], "*",
         lambda cl: cl["s3"].delete_bucket_policy(Bucket=bucket)),
    ]
    try:
        for name, actions, resource, do in attacks:
            user = f"ccpd-sc2-{name.split(':')[0]}-{tag}"
            arn = f"arn:aws:iam::{ACC}:user/{user}"
            iam.create_user(UserName=user)
            iam.put_user_policy(UserName=user, PolicyName="attack", PolicyDocument=json.dumps({
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions + ["iam:ListUsers"], "Resource": resource}]}))
            ak = iam.create_access_key(UserName=user)["AccessKey"]
            users.append((user, ak["AccessKeyId"]))
            time.sleep(1)
            cl = {s: c(s, ak["AccessKeyId"], ak["SecretAccessKey"]) for s in ("kms", "s3", "iam")}
            r = {"attack": name, "user": arn}
            t_call = time.time()
            try:
                do(cl)
                r["attack_call_s"] = round(time.time() - t_call, 3)
            except ClientError as e:
                r["attack_denied"] = e.response["Error"]["Code"]
            action, deadline = None, t_call + 90
            while time.time() < deadline and not action:
                if log.exists():
                    for line in log.read_text().splitlines():
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if rec.get("target") == arn:
                            action = rec
                            break
                if watcher.poll() is not None:
                    break
                time.sleep(0.02)
            r["watcher_action"] = action
            if action:
                t_event = ts(action["alert_event_time"])
                rb = None
                while time.time() < deadline:
                    rb = readback(iam, user)
                    if all(rb.values()):
                        break
                    time.sleep(0.05)
                t_ver = time.time()
                r.update({"readback": rb, "verified": bool(rb and all(rb.values())),
                          "event_to_verified_s": round(t_ver - t_event, 3),
                          "call_to_verified_s": round(t_ver - t_call, 3), "watcher_attempts": action.get("attempts")})
                blocked = None
                while time.time() - t_ver < 40:
                    try:
                        cl["iam"].list_users()
                    except ClientError:
                        blocked = time.time()
                        break
                    time.sleep(0.1)
                r["call_to_blocked_s"] = None if blocked is None else round(blocked - t_call, 3)
                r["original_key"] = "blocked" if blocked else "STILL WORKS after 40 s"
            res["attacks"].append(r)
    finally:
        try:
            os.killpg(watcher.pid, signal.SIGTERM)
            watcher.wait(timeout=10)
        except Exception:
            try:
                os.killpg(watcher.pid, signal.SIGKILL)
            except Exception:
                pass
        problems = []
        for u, kid in users:
            for fn in (lambda: [iam.delete_user_policy(UserName=u, PolicyName=p) for p in iam.list_user_policies(UserName=u)["PolicyNames"]],
                       lambda: [iam.detach_user_policy(UserName=u, PolicyArn=p["PolicyArn"]) for p in iam.list_attached_user_policies(UserName=u)["AttachedPolicies"]],
                       lambda: [iam.delete_access_key(UserName=u, AccessKeyId=k["AccessKeyId"]) for k in iam.list_access_keys(UserName=u)["AccessKeyMetadata"]],
                       lambda: iam.delete_user(UserName=u)):
                try:
                    fn()
                except Exception as e:
                    problems.append(f"{u}: {type(e).__name__}")
        for fn in (lambda: s3.delete_bucket_policy(Bucket=bucket), lambda: s3.delete_bucket(Bucket=bucket),
                   lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)):
            try:
                fn()
            except Exception as e:
                problems.append(type(e).__name__)
        res["cleanup_problems"] = problems

    out = ROOT / "evidence/results/autonomous"
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"sc2-{res['git_sha'][:7]}{'-dirty' if res['modified_tracked_files'] else ''}-{stamp}.json"
    path.write_text(json.dumps(res, indent=2, default=str))
    summary = [{k: a.get(k) for k in ("attack", "verified", "event_to_verified_s", "call_to_verified_s",
               "call_to_blocked_s", "original_key", "attack_denied", "watcher_attempts")} for a in res["attacks"]]
    print(json.dumps({"attacks": summary, "operator_actions": res["operator_actions"],
                      "cleanup_problems": res["cleanup_problems"], "restoration": res["restoration"]}, indent=2))
    print("written:", path)


if __name__ == "__main__":
    main()
