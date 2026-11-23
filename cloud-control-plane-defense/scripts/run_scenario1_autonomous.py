#!/usr/bin/env python3
"""Scenario 1 (multi-hop IAM privilege escalation), fully autonomous (LocalStack only).

This script performs ATTACK steps only. It never calls a containment API.
Quarantine must come from the watcher; this script only observes and verifies.
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
PROJECT = "cloud-control-plane-defense"
DEV, CICD = f"{PROJECT}-developer", f"{PROJECT}-cicd"
RO = "arn:aws:iam::aws:policy/ReadOnlyAccess"


def c(svc, ak="test", sk="test", tok=None):
    kw = dict(endpoint_url=EP, region_name=R, aws_access_key_id=ak, aws_secret_access_key=sk)
    if tok:
        kw["aws_session_token"] = tok
    return boto3.client(svc, **kw)


def sh(*cmd):
    return subprocess.check_output(cmd, cwd=ROOT, text=True).strip()


def ts(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()


def role_policies(iam, role):
    return {"inline": set(iam.list_role_policies(RoleName=role)["PolicyNames"]),
            "attached": {p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]}}


def readback(iam, user):
    inline = set(iam.list_user_policies(UserName=user)["PolicyNames"])
    attached = {p["PolicyName"] for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]}
    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    return {"deny_policy": DENY in inline | attached, "session_policy": SESS in inline | attached,
            "keys_inactive": bool(keys) and all(k["Status"] == "Inactive" for k in keys)}


def main():
    others = subprocess.run(["pgrep", "-af", "sqs_consumer|auto_soar_watcher"],
                            capture_output=True, text=True).stdout.strip()
    if others:
        sys.exit("REFUSED: consumer/watcher already running:\n" + others)
    iam, sqs = c("iam"), c("sqs")
    queue = os.environ.get("SECURITY_EVENT_QUEUE_URL") or next(
        u for u in sqs.list_queues().get("QueueUrls", []) if "security-events" in u and "dlq" not in u)
    sqs.purge_queue(QueueUrl=queue)
    time.sleep(2)

    tag = uuid.uuid4().hex[:8]
    user, target = f"ccpd-sc1-auto-{tag}", f"ccpd-sc1-target-{tag}"
    user_arn = f"arn:aws:iam::{ACC}:user/{user}"
    target_arn = f"arn:aws:iam::{ACC}:role/{target}"
    temp_policy = f"ccpd-sc1-temp-{tag}"
    before = {r: role_policies(iam, r) for r in (DEV, CICD)}

    work = Path(tempfile.mkdtemp(prefix="ccpd-sc1-"))
    log = work / "log.jsonl"
    watcher = subprocess.Popen(
        [sys.executable, "scripts/auto_soar_watcher.py", "--queue-url", queue, "--config", "config/soar.json",
         "--alerts", str(work / "alerts.jsonl"), "--state", str(work / "state.json"), "--log", str(log),
         "--duration", "240", "--execute"],
        cwd=ROOT, stdout=open(work / "watcher.out", "w"), stderr=subprocess.STDOUT, start_new_session=True)
    time.sleep(3)

    res = {"scenario": "1 multi-hop IAM privilege escalation, autonomous", "operator_actions": [],
           "git_sha": sh("git", "rev-parse", "HEAD"),
           "modified_tracked_files": sh("git", "diff", "--name-only", "HEAD", "--", "scripts", "soar", "detector", "config").split(),
           "temporary_permission": f"cicd may iam:AttachRolePolicy on {target_arn} only (removed at end)"}
    ak = k2 = None
    try:
        iam.create_role(RoleName=target, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACC}:root"}, "Action": "sts:AssumeRole"}]}))
        iam.create_user(UserName=user)
        iam.put_user_policy(UserName=user, PolicyName="entry", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{ACC}:role/{DEV}"}]}))
        iam.put_role_policy(RoleName=CICD, PolicyName=temp_policy, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": target_arn}]}))
        ak = iam.create_access_key(UserName=user)["AccessKey"]
        time.sleep(1)

        # ---- attack only: no containment calls below this line ----
        s1 = c("sts", ak["AccessKeyId"], ak["SecretAccessKey"])
        r1 = s1.assume_role(RoleArn=f"arn:aws:iam::{ACC}:role/{DEV}", RoleSessionName="sc1-dev",
                            ExternalId="cloud-control-plane-defense-developer-entry")["Credentials"]
        r2 = c("sts", r1["AccessKeyId"], r1["SecretAccessKey"], r1["SessionToken"]).assume_role(
            RoleArn=f"arn:aws:iam::{ACC}:role/{CICD}", RoleSessionName="sc1-cicd")["Credentials"]
        k2 = r2
        t_attack = time.time()
        c("iam", r2["AccessKeyId"], r2["SecretAccessKey"], r2["SessionToken"]).attach_role_policy(RoleName=target, PolicyArn=RO)
        t_attack_end = time.time()
        res["attack_call_s"] = round(t_attack_end - t_attack, 3)
        # ---- observation only ----
        action, deadline = None, t_attack + 90
        while time.time() < deadline and not action:
            if log.exists():
                for line in log.read_text().splitlines():
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("target") == user_arn:
                        action = rec
                        break
            if watcher.poll() is not None:
                break
            time.sleep(0.02)
        res["watcher_action"] = action
        if action:
            t_event = ts(action["alert_event_time"])
            rb = None
            while time.time() < deadline:
                rb = readback(iam, user)
                if all(rb.values()):
                    break
                time.sleep(0.05)
            t_verified = time.time()
            res.update({"readback": rb, "verified": bool(rb and all(rb.values())),
                        "event_to_verified_s": round(t_verified - t_event, 3),
                        "call_to_verified_s": round(t_verified - t_attack, 3),
                        "watcher_attempts": action.get("attempts")})
        # interception proof: the attacker's original key must no longer work
        try:
            c("sts", ak["AccessKeyId"], ak["SecretAccessKey"]).assume_role(
                RoleArn=f"arn:aws:iam::{ACC}:role/{DEV}", RoleSessionName="again",
                ExternalId="cloud-control-plane-defense-developer-entry")
            res["reuse_original_key"] = "STILL WORKS (interception failed)"
        except ClientError as e:
            res["reuse_original_key"] = "blocked: " + e.response["Error"]["Code"]
        # informational only: does the already-issued session survive? (item 4 gap)
        try:
            c("iam", k2["AccessKeyId"], k2["SecretAccessKey"], k2["SessionToken"]).list_role_policies(RoleName=target)
            res["issued_session_after_quarantine"] = "STILL WORKS (session revocation not effective on this emulator)"
        except ClientError as e:
            res["issued_session_after_quarantine"] = "blocked: " + e.response["Error"]["Code"]
        after = {r: role_policies(iam, r) for r in (DEV, CICD)}
        res["policies_added_to_shared_roles"] = {
            r: {"inline": sorted(after[r]["inline"] - before[r]["inline"] - {temp_policy}),
                "attached": sorted(after[r]["attached"] - before[r]["attached"])} for r in before}
    finally:
        try:
            os.killpg(watcher.pid, signal.SIGTERM)
            watcher.wait(timeout=10)
        except Exception:
            try:
                os.killpg(watcher.pid, signal.SIGKILL)
            except Exception:
                pass
        cleanup = []
        def run(label, fn):
            try:
                fn()
            except Exception as e:
                cleanup.append(f"{label}: {type(e).__name__}")
        for r in (DEV, CICD):
            for name in sorted(role_policies(iam, r)["inline"] - before[r]["inline"]):
                run(f"remove inline {name} from {r}", lambda r=r, name=name: iam.delete_role_policy(RoleName=r, PolicyName=name))
            for arn in sorted(role_policies(iam, r)["attached"] - before[r]["attached"]):
                run(f"detach {arn} from {r}", lambda r=r, arn=arn: iam.detach_role_policy(RoleName=r, PolicyArn=arn))
        run("detach target", lambda: iam.detach_role_policy(RoleName=target, PolicyArn=RO))
        run("delete target", lambda: iam.delete_role(RoleName=target))
        try:
            for n in iam.list_user_policies(UserName=user)["PolicyNames"]:
                iam.delete_user_policy(UserName=user, PolicyName=n)
            for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]:
                iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
            for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
            iam.delete_user(UserName=user)
        except Exception as e:
            cleanup.append("user cleanup: " + type(e).__name__)
        res["cleanup_problems"] = cleanup
        res["roles_restored_to_original"] = all(role_policies(iam, r) == before[r] for r in before)

    out = ROOT / "evidence/results/autonomous"
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"sc1-{res['git_sha'][:7]}{'-dirty' if res['modified_tracked_files'] else ''}-{stamp}.json"
    path.write_text(json.dumps(res, indent=2, default=str))
    keys = ("verified", "readback", "attack_call_s", "event_to_verified_s", "call_to_verified_s", "watcher_attempts",
            "reuse_original_key", "issued_session_after_quarantine", "policies_added_to_shared_roles",
            "cleanup_problems", "roles_restored_to_original", "operator_actions")
    print(json.dumps({k: res.get(k) for k in keys}, indent=2))
    print("written:", path)


if __name__ == "__main__":
    main()
