"""Bypass probes against the detector. Prints CAUGHT/MISSED; asserts nothing."""
import sys
import time

sys.path.insert(0, "tests")
from test_cloud_control_plane_defense import make_event  # noqa: E402
from detector.cloud_control_plane_detector import CloudControlPlaneDetector  # noqa: E402

ACCT = "000000000000"
USER_A = f"arn:aws:iam::{ACCT}:user/attacker"
USER_V = f"arn:aws:iam::{ACCT}:user/victim"
DEV = "cloud-control-plane-defense-developer"
CICD = "cloud-control-plane-defense-cicd"
PROD = "cloud-control-plane-defense-production"


def kinds(alerts):
    return [a["detection_type"] for a in alerts]


def show(tag, outcome, detail):
    print(f"[{tag}] {outcome:8} {detail}")


def assume(d, eid, caller, ctype, role, session):
    assumed = f"arn:aws:sts::{ACCT}:assumed-role/{role}/{session}"
    out = d.process_event(make_event(
        event_id=eid, event_name="AssumeRole", event_source="sts.amazonaws.com",
        event_time="2026-11-26T12:00:00Z", caller_arn=caller, caller_type=ctype,
        request={"roleArn": f"arn:aws:iam::{ACCT}:role/{role}"},
        response={"assumedRoleUser": {"arn": assumed}}))
    return assumed, out


def put_policy(d, eid, caller, ctype, t="2026-11-26T12:00:00Z"):
    return d.process_event(make_event(
        event_id=eid, event_name="PutUserPolicy", event_source="iam.amazonaws.com",
        event_time=t, caller_arn=caller, caller_type=ctype,
        request={"userName": "victim"}))


def secret(d, eid, name, t):
    return d.process_event(make_event(
        event_id=eid, event_name="GetSecretValue",
        event_source="secretsmanager.amazonaws.com", event_time=t,
        caller_arn=f"arn:aws:sts::{ACCT}:assumed-role/dev-role/s1",
        caller_type="AssumedRole", request={"secretId": name}))


# --- Role chains and attribution ---
d = CloudControlPlaneDetector()
s1, o1 = assume(d, "c1-1", USER_A, "IAMUser", DEV, "a")
s2, o2 = assume(d, "c1-2", s1, "AssumedRole", CICD, "b")
s3, o3 = assume(d, "c1-3", s2, "AssumedRole", PROD, "c")
show("C1", "CAUGHT" if "privileged_role_chain" in kinds(o1 + o2 + o3) else "MISSED",
     "control: developer->cicd->production chain")

d = CloudControlPlaneDetector()
cur, ct, allout = USER_A, "IAMUser", []
for i, role in enumerate([DEV, "extra-role", CICD, PROD]):
    cur, out = assume(d, f"c2-{i}", cur, ct, role, "s")
    ct = "AssumedRole"
    allout += out
show("C2", "CAUGHT" if "privileged_role_chain" in kinds(allout) else "MISSED",
     "extra hop inserted: developer->extra->cicd->production")

d = CloudControlPlaneDetector()
cur, ct = USER_A, "IAMUser"
for i in range(1, 6):
    cur, _ = assume(d, f"c3-{i}", cur, ct, f"hop-role-{i}", "s")
    ct = "AssumedRole"
q = [a.get("quarantine_principal_arn") for a in put_policy(d, "c3-act", cur, "AssumedRole")]
show("C3", "CAUGHT" if q and all(x == USER_A for x in q) else "MISSED",
     f"5-hop chain, attribution -> {q}")

d = CloudControlPlaneDetector()
sess, _ = assume(d, "c4-1", USER_A, "IAMUser", DEV, "shared")
assume(d, "c4-2", USER_V, "IAMUser", DEV, "shared")
q = [a.get("quarantine_principal_arn") for a in put_policy(d, "c4-act", sess, "AssumedRole")]
show("C4", "CAUGHT" if q and all(x is None for x in q) else "MISSED",
     f"same session name used by two principals, attribution -> {q}")

# --- Timestamps ---
d = CloudControlPlaneDetector()
r = []
for i, n in enumerate(["x", "y", "z"]):
    r += secret(d, f"t1-{i}", n, f"2026-11-26T12:00:0{i}Z")
show("T1", "CAUGHT" if "secret_enumeration_burst" in kinds(r) else "MISSED",
     "control: 3 distinct secrets in 3 s")

d = CloudControlPlaneDetector()
secret(d, "t2-forged", "poison", "2099-01-01T00:00:00Z")
r = []
for i, n in enumerate(["x", "y", "z"]):
    r += secret(d, f"t2-{i}", n, f"2026-11-26T12:00:0{i}Z")
show("T2", "CAUGHT" if "secret_enumeration_burst" in kinds(r) else "MISSED",
     "forged 2099 event first, then honest burst")

for year in ("2000", "2099"):
    d = CloudControlPlaneDetector()
    r = put_policy(d, f"t3-{year}", USER_A, "IAMUser", t=f"{year}-01-01T00:00:00Z")
    show("T3", "CAUGHT" if "iam_privilege_escalation" in kinds(r) else "MISSED",
         f"PutUserPolicy stamped {year}")

# --- Replay and event-ID tricks ---
d = CloudControlPlaneDetector()
first = put_policy(d, "r1", USER_A, "IAMUser")
second = put_policy(d, "r1", USER_A, "IAMUser")
show("R1", "CAUGHT" if first and not second else "MISSED", "same event replayed")

d = CloudControlPlaneDetector()
d.process_event(make_event(event_id="squat", event_name="DescribeKey"))
r = put_policy(d, "squat", USER_A, "IAMUser")
show("R2", "CAUGHT" if r else "MISSED", "malicious event reusing a benign event's ID")

d = CloudControlPlaneDetector(deduplication_limit=5)
put_policy(d, "r3-a", USER_A, "IAMUser")
for i in range(5):
    d.process_event(make_event(event_id=f"r3-f{i}", event_name="DescribeKey"))
again = put_policy(d, "r3-a", USER_A, "IAMUser")
show("R3", "INFO", f"replay after ID eviction re-alerts: {bool(again)} (duplicate, not suppression)")

# --- Flood (detector only, not the watcher) ---
d = CloudControlPlaneDetector()
n = 20000
t0 = time.perf_counter()
for i in range(n):
    d.process_event(make_event(event_id=f"flood-{i}", event_name="DescribeKey"))
dt = time.perf_counter() - t0
mal = put_policy(d, "flood-mal", USER_A, "IAMUser")
show("F1", "CAUGHT" if mal else "MISSED",
     f"{n} benign events in {dt:.2f}s ({n/dt:.0f}/s), seen_ids={len(d._seen_ids)}, then malicious event")

d = CloudControlPlaneDetector()
for i in range(5000):
    assume(d, f"f2-{i}", USER_A, "IAMUser", DEV, f"s{i}")
show("F2", "INFO", f"5000 unique sessions -> role_origins={len(d._role_origins)}, "
     f"role_sessions={len(d._role_sessions)} (unbounded if 5000)")
