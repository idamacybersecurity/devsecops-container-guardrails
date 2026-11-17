# Zero-Trust Cloud Control-Plane Defense
## Engineering Report and Adversarial Validation

**Environment:** LocalStack on an EC2-hosted development environment
**Cloud spend:** $0.00 target; AWS services emulated locally
**Submission deadline:** Friday, 20 November 2026
**Report status:** Updated evidence-backed engineering report; final evidence audit and PDF export remain outstanding.

---

## 1. Executive summary

This project implements a local cloud control-plane security environment and
defense workflow covering infrastructure policy enforcement, stateful IAM
role-chain attribution, security-event detection, IAM quarantine, and
out-of-band drift remediation.

The implementation has passed a 67-test automated regression suite. Live
adversarial exercises demonstrated multi-hop IAM attribution, KMS rotation
defense-evasion detection, S3 bucket-policy deletion detection, verified IAM
quarantine, and remediation of unauthorized security-group and IAM trust
changes.

StopLogging state-transition detection was demonstrated using a separate
independent polling monitor. The monitor observed a disposable trail transition
from IsLogging=true to IsLogging=false and emitted a CRITICAL alert, which was
saved to evidence/transcripts/stoplogging-state-alert.json. Logging was then
restored, and the main audit trail remained enabled. Native StopLogging event
delivery, attacker attribution, and SOAR containment for this alert remain
unverified.

## 2. Architecture

The system has four principal layers:

1. **Infrastructure and policy gate:** Terraform provisions the emulated
   network, IAM, KMS, S3, Secrets Manager, CloudTrail, and event-routing
   resources. Conftest/OPA evaluates planned changes before deployment.
2. **Detection:** The Python detector parses CloudTrail/EventBridge records,
   tracks AssumeRole relationships, applies kill-chain rules, suppresses
   duplicates, and persists detector state.
3. **Response:** The SOAR responder validates alert identity and severity,
   protects the break-glass principal, defaults to dry-run, and supports
   explicit execution of IAM quarantine controls.
4. **Drift remediation:** The reconciler compares live resource state with an
   approved baseline, records forensic snapshots, performs targeted rollback,
   and verifies the restored state.

See `architecture.mmd` for the architecture diagram source.

## 3. Infrastructure and policy enforcement

The Terraform environment includes a VPC with public and private subnets,
security groups, IAM role tiers, KMS, encrypted S3 audit/forensics buckets,
Secrets Manager, CloudTrail, EventBridge, SQS, and a dead-letter queue.

The OPA policy gate is intended to reject wildcard IAM actions, dangerous
privilege-escalation permission combinations, missing encryption controls, and
public security-group ingress. See `OPA-POLICY-SPECIFICATION.md` and the
authoritative Rego source in `policies/`.

The CloudTrail audit trail was observed logging and delivering compressed log
objects to the audit bucket. The audit bucket uses SSE-KMS and a restricted
CloudTrail write policy.

## 4. Stateful detection and attribution

`detector/cloud_control_plane_detector.py` processes CloudTrail/EventBridge
records and maintains state for cross-role AssumeRole attribution. Detection
logic covers:

- IAM privilege-escalation API activity.
- Native defense-evasion event detection for bucket-policy deletion and
  KMS key-rotation disablement.
- Separate independent CloudTrail state polling for StopLogging logging-state
  transitions; this monitor is not native event parsing or SOAR integration.
- High-velocity secret retrieval across distinct resources within a
  30-second window.

The detector validates event structure and timestamps, redacts sensitive
fields, persists state atomically, and suppresses duplicate alerts.

### Multi-hop IAM attack

A compromised developer identity assumed a CI role and attempted a privileged
IAM action. The detector attributed the escalation to the originating
developer identity and generated high-severity alerts. Native CloudTrail
records were replayed into an isolated SQS test queue for consumer validation;
the main security queue was not used for that replay.

The replay demonstrated alert generation and attribution. It should not be
described as proof that every native CloudTrail event was automatically routed
to SQS by LocalStack.

## 5. SOAR containment

`soar/cloud_soar_responder.py` implements dry-run-by-default behavior and
requires explicit `--execute` for mutations. It validates account, event,
severity, caller identity, and break-glass protection before acting.

The implemented containment controls include:

- An inline explicit DenyAll policy.
- STS session-revocation policy using an `aws:TokenIssueTime` condition.
- Deactivation of active IAM user access keys.
- Independent readback of applied IAM controls.

### Verified containment exercises

**KMS rotation attack:** `kms:DisableKeyRotation` was executed using a
disposable attacker identity. A native CloudTrail event was found, the detector
generated an alert, SOAR containment was executed, IAM controls were
independently verified, and key rotation was restored.

**S3 bucket-policy attack:** `s3:DeleteBucketPolicy` was executed using a
disposable attacker identity. Native CloudTrail event ID
`6f06c1d9-68fb-4b27-8d78-125298dceab1` was captured. The detector generated a
critical defense-evasion alert. SOAR executed quarantine, and independent
IAM/S3 verification confirmed the DenyAll policy, session-revocation policy,
inactive access key, and restoration of the original bucket policy.

### Session-revocation qualification

LocalStack accepted and returned the configured IAM policies. This verifies
policy application and readback in the emulator; it does not independently
prove invalidation of an already-issued STS token in the way a live AWS
integration test could.

## 6. Ten-run SOAR benchmark

The recorded benchmark completed ten consecutive SOAR executions:

| Metric | Recorded result |
|---|---:|
| Successful runs | 10 / 10 |
| Failed runs | 0 |
| Mean execution latency | 0.253783868 s |
| Maximum execution latency | 0.317171893 s |
| Mean event-to-verified latency | 0.253797100 s |
| Maximum event-to-verified latency | 0.317188000 s |
| Independently verified controls per run | 3 / 3 |

Evidence file: `evidence/runtime/soar-ten-run-benchmark.json`.

**Measurement qualification:** This benchmark measures the implemented
simulated-alert-to-SOAR execution and verification path. It is not evidence of
a complete native CloudTrail event timestamp-to-quarantine measurement across
the entire AWS control-plane pipeline.

## 7. Out-of-band drift and self-healing

`drift/drift_reconciler.py` compares live LocalStack resource state with the
approved baseline and Terraform configuration digest. It supports check-only
and explicit remediation modes, records forensic snapshots, and independently
checks the restored resource state.

### Public ingress injection

An unauthorized public SSH ingress rule was added to the security group.
The reconciler detected the drift, recorded a forensic snapshot, removed the
unauthorized exposure, and verified that public SSH ingress was absent.

### Rogue IAM trust injection

A disposable attacker identity added a rogue trust statement to the Developer
role while preserving the original approved trust statement. The reconciler
reported drift, captured the rogue trust state, restored the approved trust
policy, and independently verified that the live trust matched the baseline.

Forensic snapshot examples:

- `evidence/forensic-snapshots/drift-before-remediation-20261117T170705046237Z.json`
- `evidence/forensic-snapshots/drift-before-remediation-20261117T183849799033Z.json`

### Baseline integrity qualification

The baseline is HMAC-protected and the reconciler checks the Terraform
configuration digest. The HMAC key is stored on the same host as the baseline;
a privileged attacker controlling that host could potentially replace both.
An independently protected signing key or remote immutable baseline would
strengthen this design.

## 8. Adversarial scenario results

| Scenario | Result | Evidence-backed qualification |
|---|---|---|
| 1. Multi-hop IAM privilege escalation | Demonstrated | Role-chain attribution, escalation alerting, and quarantine exercised. Native records were replayed through an isolated queue for consumer validation. |
| 2. CloudTrail defense evasion | Partially demonstrated | Native KMS and S3 policy-deletion events detected and contained. A separate state poller detected StopLogging by observing the trail transition to IsLogging=false and emitted a CRITICAL alert. Native StopLogging event delivery, attacker attribution, and SOAR containment for this alert remain unverified. |
| 3. Out-of-band drift persistence | Demonstrated | Public ingress and rogue IAM trust injected, snapshotted, remediated, and independently verified. |
| 4. Unit and regression suite | Passed | 67 tests passed; focused break-glass/malformed-event tests also passed. |

### StopLogging state-transition detection record

A separate monitor was implemented in
`scripts/stoplogging_state_detector.py`. It polls CloudTrail trail status and
compares the observed state with the enabled baseline.

Verified exercise:

1. Created disposable trail `ccpd-stoplogging-state-detection-20261117`.
2. Confirmed baseline `IsLogging=true`.
3. Started the monitor and observed `MONITOR_READY`.
4. Executed `cloudtrail stop-logging` against the disposable trail.
5. The monitor observed `IsLogging=false` and emitted
   `STOPLOGGING_STATE_CHANGE_DETECTED`.
6. The alert recorded severity `CRITICAL`, alert type
   `cloudtrail_logging_state_disabled`, and detection method
   `independent_cloudtrail_state_polling`.
7. Saved alert JSON to `evidence/transcripts/stoplogging-state-alert.json`.
8. Restored logging with `start-logging` and verified the disposable trail
   returned to `IsLogging=true`. The main audit trail also remained enabled.

The alert has `native_cloudtrail_event_id: null`. Earlier attempts to retrieve
a native StopLogging event through CloudTrail event history, S3 log delivery,
and EventBridge did not produce one. A benign S3 control event also failed to
arrive through the tested EventBridge integration.

This demonstrates state-transition detection and recovery, not native
StopLogging event capture, attacker-principal attribution, or automated SOAR
containment for this alert.

**Screenshot placeholder:** `evidence/screenshots/stoplogging-state-transition-detection.png`
(Presence of this screenshot has not yet been verified.)

## 9. Automated testing

Recorded test outcomes:

- Full regression suite: **67 passed in 0.40 seconds**.
- Focused break-glass and malformed-event tests: **5 passed**.
- Benign-event false-positive regression tests: **6 passed**.
- `git diff --check`: clean at the recorded validation point.

These results establish the recorded pass rate for the executed tests. They
do not establish exhaustive code coverage or correctness against every AWS
service behavior.

## 10. Security boundaries and known limitations

- LocalStack is an emulator; successful API responses do not prove all AWS
  service-side semantics.
- Native StopLogging event capture remains unverified; independent state-polling detection was demonstrated, but does not attribute the actor or trigger SOAR containment.
- STS token invalidation semantics were not proven against live AWS.
- The SOAR benchmark is not a full native event-to-quarantine benchmark.
- The HMAC key and baseline share a host.
- The explicit DenyAll inline policy is an IAM policy attachment; it is not
  represented as a formal permissions boundary.
- The LocalStack-only execution boundary must be maintained to preserve the
  zero-cloud-spend requirement.

## 11. Evidence and submission status

Evidence already recorded includes native CloudTrail event JSON for the KMS
and S3 attacks, detector alert JSON, SOAR execution and independent
verification, drift snapshots, the ten-run benchmark JSON, and the
StopLogging state-polling alert at
`evidence/transcripts/stoplogging-state-alert.json`. The corresponding monitor
is `scripts/stoplogging_state_detector.py`.

The StopLogging exercise also verified restoration of the disposable trail and
confirmed that the main audit trail remained enabled. The screenshot
`evidence/screenshots/stoplogging-state-transition-detection.png` is a
placeholder only; its presence has not been verified. Screenshots and terminal
transcripts must be audited against the actual submission folder before final
sign-off.

## 12. Conclusion

The project demonstrates a functioning local cloud control-plane defense
workflow across infrastructure policy validation, stateful IAM attribution,
alerting, controlled IAM quarantine, forensic drift capture, and targeted
self-healing. The regression suite and ten-run SOAR benchmark passed at the
recorded values.

The report deliberately distinguishes verified behavior from limitations.
StopLogging state-transition detection and restoration were demonstrated using
independent polling, but native StopLogging event capture and SOAR containment
for that alert remain unverified. Live AWS STS revocation semantics and full
end-to-end latency also remain unverified and are not presented as completed
proof.
