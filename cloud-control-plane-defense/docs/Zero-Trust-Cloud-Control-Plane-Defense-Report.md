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

The implementation has passed a 240-test automated regression suite
(59.88 seconds at the recorded validation point). Additional Phase 2
validation includes Terraform policy tests, Rego mutation testing, live
LocalStack drift mutations, and a verified quarantine-and-rollback exercise.
Live adversarial exercises demonstrated multi-hop IAM attribution, KMS
rotation defense-evasion detection, S3 bucket-policy deletion detection,
verified IAM quarantine, and remediation of unauthorized security-group and
IAM trust changes.

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

A new ten-run LocalStack benchmark was executed with independent verification
of the responder's containment controls. All ten runs passed the benchmark
criteria, and all ten completed in under one second.

| Metric | Latest recorded result |
|---|---:|
| Successful runs | 10 / 10 |
| Failed runs | 0 |
| Independently verified runs | 10 / 10 |
| Runs under one second | 10 / 10 |
| Mean responder execution latency | 0.692625 s |
| Maximum responder execution latency | 0.775812 s |
| Mean synthetic event-to-verified latency | 0.692646 s |
| Maximum synthetic event-to-verified latency | 0.775827 s |
| Independently verified controls per run | 3 / 3 |

Evidence file:
`evidence/runtime/soar-ten-run-benchmark-20261125-10of10.json`

SHA-256:
`668bd6de61d9400677834bfa6b5a0a3f7fec758053779075b62708290159ac3a`

### IAM API timing instrumentation

The benchmark recorded 120 IAM API calls across the ten runs. No API-call
errors were recorded.

| IAM operation | Calls | Mean duration | Maximum duration |
|---|---:|---:|---:|
| put_user_policy | 20 | 0.073608 s | 0.214205 s |
| get_user_policy | 40 | 0.068025 s | 0.170501 s |
| list_access_keys | 40 | 0.047276 s | 0.103274 s |
| update_access_key | 10 | 0.046748 s | 0.080389 s |
| get_user | 10 | 0.036982 s | 0.051409 s |

Timing analysis:
`evidence/runtime/soar-iam-api-timing-analysis-20261125.json`

SHA-256:
`a1723bfcbfa4405ea60808d0d68ae42ceecd66228369d719790ade87ff83d4be`

### Measurement qualification

This benchmark measures the LocalStack simulated-alert-to-SOAR responder
execution and independent IAM verification path. Its event-to-verified timer
starts immediately before responder execution; it does not measure native
CloudTrail event generation, delivery, detection, queueing, or real AWS policy
propagation.

The results therefore demonstrate that the tested responder workflow
completed and independently verified its controls in under one second across
ten consecutive LocalStack runs. They do not establish sub-second
native-event-to-attacker-denial performance in live AWS.

The earlier benchmark record
`evidence/runtime/soar-ten-run-benchmark.json` represents a previous run and
should be treated as historical evidence, not as the source for the latest
figures.

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

The approved drift baseline is protected by a detached Ed25519 signature.
The reconciler verifies the signature with the trusted public key and signer
identity in `evidence/runtime/ccpd-allowed-signers` before accepting the
baseline. It also checks the Terraform configuration digest.

The signing workflow was tested across two machines: the baseline was signed
on the Windows signing workstation using the passphrase-protected Ed25519
private key, and the resulting detached signature was independently verified
on EC2 using the trusted public key. The Windows and EC2 baseline files were
confirmed identical by SHA-256 before signing. The production baseline and
existing production signature were not modified during this test.

This demonstrates cross-machine signature verification, not immunity from
signing-workstation compromise. A compromised Windows account, local
administrator, or SYSTEM process could access the private key or misuse it.
The test also does not prove that no duplicate private-key copy exists on EC2;
searches of selected host locations did not find a matching key, but were not
an exhaustive proof of absence. The private signing key should remain
restricted and protected, and any suspected compromise requires key rotation
and re-signing the approved baseline.

## 8. Adversarial scenario results

| Scenario | Result | Evidence-backed qualification |
|---|---|---|
| 1. Multi-hop IAM privilege escalation | Demonstrated | Role-chain attribution, escalation alerting, and quarantine exercised. Native records were replayed through an isolated queue for consumer validation. |
| 2. CloudTrail defense evasion | Partially demonstrated | Native KMS and S3 policy-deletion events detected and contained. A separate state poller detected StopLogging by observing the trail transition to IsLogging=false and emitted a CRITICAL alert. Native StopLogging event delivery, attacker attribution, and SOAR containment for this alert remain unverified. |
| 3. Out-of-band drift persistence | Demonstrated | Public ingress and rogue IAM trust injected, snapshotted, remediated, and independently verified. |
| 4. Unit and regression suite | Passed | 240 pytest tests passed in 59.88 seconds at the recorded validation point. Separate Terraform/Rego validation is reported in Section 9.5. |

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

## 9. Automated testing

Recorded test outcomes:

- Full pytest regression suite: **240 passed in 59.88 seconds**.
- Detection and bypass regression module: **100 passed**.
- Replay-protection focused selection: **4 passed**.
- IAM drift tests: **7 passed**.
- KMS drift tests: **5 passed**.
- Live-collector test module: **3 passed**.
- Terraform/Rego policy verification: **31 passed**.
- Rego deny-rule mutation campaign: **14/14 mutants killed; zero survivors**.
  The harness treats any nonzero Conftest exit as a killed mutant, so this is
  an observed campaign result rather than proof that every mutant failed
  specifically on a policy assertion.
- `git diff --check`: clean at the recorded validation point.

The focused pytest results are overlapping subsets or targeted modules and
must not be added to the full-suite total. Rego verification and mutation
testing are separate from pytest. These results do not establish exhaustive
code coverage or correctness against every AWS service behavior.

## 10. Security boundaries and known limitations

- LocalStack is an emulator; successful API responses do not prove all AWS
  service-side semantics.
- Native StopLogging event capture remains unverified; independent state-polling detection was demonstrated, but does not attribute the actor or trigger SOAR containment.
- STS token invalidation semantics were not proven against live AWS.
- The SOAR benchmark is not a full native event-to-quarantine benchmark.
- The baseline uses a detached Ed25519 signature created with a
  passphrase-protected signing key on the Windows workstation and verified
  on EC2. The signing workflow was tested across both machines. The EC2
  host stores the baseline, signature, and trusted public-key configuration;
  a privileged attacker able to modify the trusted signer configuration or
  verification code could bypass local verification. The searches performed
  did not establish that no duplicate private-key copy exists on EC2.
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
confirmed that the main audit trail remained enabled. A screenshot for the StopLogging state-transition exercise has not been
verified in the repository evidence folder. Check the actual submission folder
before claiming screenshot evidence or completing final sign-off. Screenshots
and terminal transcripts must be audited against the submitted artifacts.

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

---

## 9. Phase 2 — Harden, Prove and Extend

### 9.1 Scope and execution boundary

Phase 2 extends the existing zero-cost LocalStack-based cloud control-plane
defense implementation. Experiments use the existing host, open-source
components, and the free LocalStack tier. No paid AWS services or paid APIs
are required by the intended test workflow.

Previously submitted Phase 2 items 1–5 remain part of the project evidence.
This section records the additional hardening, adversarial validation,
performance investigation, and evidence gathered during the subsequent work.

### 9.2 Autonomous attack and containment validation

The Phase 2 evidence includes autonomous scenario executions covering
cross-principal IAM activity, CloudTrail defense evasion, unauthorized IAM
changes, secrets enumeration, and slow-and-low enumeration.

Scenario results are retained as machine-readable JSON under
`evidence/results/autonomous/`. These records are the source of truth for
individual execution outcomes. A scenario is not considered fully proven
merely because its runner or detection rule exists.

The cross-user access-key containment exercise demonstrated that the
attacker identity could be quarantined without quarantining the victim.
Independent cleanup verification confirmed that disposable test identities
were removed, the isolated queue was empty, and original/test EventBridge
targets were preserved.

Additional evidence covers CloudTrail deletion attempts, SSM parameter
enumeration, and slow-and-low secrets enumeration. Synthetic event tests and
native service-event delivery are distinguished in the underlying evidence;
they must not be treated as equivalent.

### 9.3 Session-aware containment and recovery

The Phase 2 implementation extends IAM containment and recovery handling
with session-aware quarantine and rollback support.

A live LocalStack rollback demonstration exercised one uniquely generated,
disposable IAM user. The 25-check run verified quarantine, a non-mutating
rollback dry-run, removal of both quarantine policies, restoration of the
originally active access key and original inline policy, audit recording of
the operator and reason, rejection of a duplicate rollback, and cleanup of
the disposable user. The durable result is
`evidence/phase2/gapfill/rollback-live-20261127T135152Z.json`.

This demonstration did not revoke shared role-chain principals and does not
validate multi-principal rollback. Containment and rollback claims must be
interpreted against the recorded LocalStack tests and independent readbacks.
LocalStack acceptance or readback of an IAM policy does not establish that an
already-issued STS session token would be invalidated in live AWS.

### 9.4 Drift detection and integrity protection

Phase 2 extends drift coverage beyond the original public-ingress and IAM
trust-policy demonstrations. The evidence set includes additional IAM,
KMS, CloudTrail, and alternate-path drift work, together with baseline
integrity artifacts.

Historical HMAC integrity artifacts and their validation evidence are
retained under `evidence/phase2/` as records of the earlier implementation.
They are not the current baseline trust mechanism. The current implementation
uses a detached Ed25519 signature, with signing performed on the Windows
workstation and verification on EC2. The cross-machine signing and verification
workflow was tested. The current trust boundary and its limitations are
documented in the Baseline integrity qualification and Security boundaries
sections above.

### 9.5 Terraform and policy-as-code validation

Terraform plans, policy validation artifacts, and regression outputs are
retained with the Phase 2 evidence. The policy gate is intended to reject
unsafe infrastructure changes before deployment.

A configured CI workflow or a policy file alone is not proof that every
required negative case has passed. Claims about individual Rego rules,
Terraform plan rejection, and pull-request execution must be supported by
the corresponding recorded test output.

### 9.6 Native event-to-containment performance

The isolated native-event benchmark is reported separately from the earlier
SOAR-only execution benchmark.

The latest boundary-aligned native-event benchmark supersedes the earlier
ten-run measurement below as the current performance result.

| Measurement | Latest result |
|---|---:|
| Benchmark runs | 10 |
| Independently verified quarantines | 10/10 |
| End-to-end results under 1 second | 10/10 |
| Median event-time-to-verified | 0.458 seconds |
| P90 event-time-to-verified | 0.503 seconds |
| Maximum event-time-to-verified | 0.564 seconds |
| Authentication-denial checks | 10/10 |
| Mean authentication-denial time | 4.650 seconds |
| Maximum authentication-denial time | 4.770 seconds |

Authentication-denial timing is a separate measurement and is not included
in event-time-to-verified containment latency. The native benchmark evidence
is retained at
`evidence/results/native-eventtime/9e9fc60-dirty-native-boundary-aligned-20261127-20261127T061208Z.json`.

An earlier ten-run native benchmark recorded 9/10 results under one second,
with a median of 0.467 seconds, P90 of 0.553 seconds, and a maximum of
18.167 seconds. That historical outlier was not conclusively explained.
The newer boundary-aligned run achieved 10/10 under one second; it does not
retroactively establish the cause of the earlier outlier.

The scheduled-versus-manual snapshot experiment identified an association
between scheduled snapshot activity and long calls in the earlier experiment.
This is an experimental observation, not proof that snapshot activity caused
the delay.

The latest ten-run SOAR-only benchmark in Section 6 recorded a mean
responder execution latency of 0.692625 seconds. It measures a different
portion of the workflow and must not be presented as the end-to-end
event-to-verified-quarantine latency.

Detailed methodology, measurements, integrity records, and qualifications
are documented in
`evidence/phase2/SECTION_B_FINAL_REPORT.md`.

### 9.7 Evidence and remaining limitations

Phase 2 evidence is retained in `evidence/phase2/` and
`evidence/results/autonomous/`, including benchmark records, autonomous
scenario results, bypass and regression artifacts, Terraform evidence,
integrity artifacts, and supporting probe output.

The following limitations remain material:

- The earlier 18.167-second end-to-end outlier remains unexplained; the later boundary-aligned native benchmark achieved 10/10 under one second.
- The snapshot experiment does not establish causation.
- LocalStack behavior does not establish all live AWS service semantics.
- LocalStack policy readback does not prove invalidation of an already-issued
  STS token in live AWS.
- Native CloudTrail StopLogging event delivery and automated SOAR containment
  for that native event remain unverified. Independent state-transition
  polling demonstrated detection, but does not establish native event
  attribution or SOAR containment.
- Synthetic event injection is not proof of native CloudTrail event delivery.
- Historical HMAC evidence remains archived, but the current baseline
  integrity mechanism is detached Ed25519 signing. EC2 stores the trusted
  public-key configuration and verification code; a privileged host attacker
  able to modify either could bypass local verification. The searches
  performed did not prove that no duplicate private-key copy exists on EC2.
  Compromise of the Windows signing workstation could also expose or misuse
  the private signing key.

The detailed Phase 2 performance report and evidence records take precedence
for the measurements and individual experiment outcomes. Test totals and
scenario completion claims must be taken from the corresponding captured
test outputs, not inferred from the existence of test files or scripts.
