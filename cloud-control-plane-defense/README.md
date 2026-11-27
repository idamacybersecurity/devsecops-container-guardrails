# Zero-Trust Cloud Control-Plane Defense

A LocalStack-based security engineering project for detecting cloud control-plane attacks, attributing multi-hop IAM role assumptions, containing compromised identities, and detecting and remediating unauthorized infrastructure drift.

The project combines event-driven detection, IAM-focused SOAR response, replay-resistant event processing, signed drift baselines, infrastructure policy checks, and automated security regression tests.

## Environment and cost boundary

- Docker and LocalStack for AWS API emulation
- Terraform for infrastructure provisioning and approved configuration
- Conftest / OPA for pre-deployment policy evaluation
- Python 3 and boto3 for detection, response, and drift inspection
- pytest for automated regression and adversarial tests
- OpenSSH `ssh-keygen` for detached Ed25519 baseline signatures

**Cost boundary:** The project is designed and exercised against LocalStack. The intended execution workflow does not require paid AWS resources. Results reported here are LocalStack results unless explicitly stated otherwise.

## Architecture and components

| Path | Responsibility |
|---|---|
| `terraform/` | Infrastructure definitions and approved configuration |
| `policies/` | OPA / Rego infrastructure policy checks |
| `detector/cloud_control_plane_detector.py` | CloudTrail/EventBridge event parsing, identity attribution, and anomaly detection |
| `detector/sqs_consumer.py` | SQS event consumption, replay handling, and alert persistence |
| `soar/cloud_soar_responder.py` | Validated, dry-run-by-default IAM containment |
| `drift/drift_reconciler.py` | Signed-baseline verification, live inventory comparison, forensic snapshots, and targeted remediation |
| `tests/` | Automated regression, collector, and security tests |
| `scripts/` | Validation, benchmark, and operational utilities |
| `evidence/` | Runtime results, test evidence, and forensic artifacts |
| `docs/` | Detailed architecture, methodology, results, limitations, and submission report |

## Verified project results

The results below reflect the latest recorded evidence available for this README revision. Focused test counts are subsets of the full suite and must not be added to the full-suite total.

### Automated tests

- Full regression suite: **240 passed**.
- Detection and adversarial test module: **100 passed**.
- Replay-protection focused tests: **4 passed**.
- IAM drift test module: **7 passed**.
- KMS drift test module: **5 passed**.
- Live collector test module: **3 passed**.
- Terraform/Rego policy verification: **31 passed**.
- Rego deny-rule mutation campaign: **14/14 mutants killed; zero survivors**.
  The harness treats any nonzero Conftest exit as a killed mutant, so this is an observed campaign result rather than proof that every mutant failed specifically on a policy assertion.
- `git diff --check` passed during the recorded regression validation.

These results cover detection, event and identity validation, replay handling, IAM inventory collection, KMS policy collection, and CloudTrail/S3 collector behavior.

### Native event-time containment benchmark

The latest native benchmark completed **10/10 verified quarantine runs**, with all ten under one second.

| Measurement | Result |
|---|---:|
| Verified quarantine runs | 10/10 |
| Runs under one second | 10/10 |
| Median event-to-verified | 0.458 s |
| P90 event-to-verified | 0.503 s |
| Maximum event-to-verified | 0.564 s |
| Authorization-denial checks | 10/10 |
| Mean authorization-denial time | 4.650 s |
| Credential-authentication-denied observations | 0/10 |

Event-to-verified measures the time from the native event timestamp to verified quarantine. Authorization-denial timing is a separate measurement and is not sub-second.

Evidence:

`evidence/results/native-eventtime/9e9fc60-dirty-native-boundary-aligned-20261127-20261127T061208Z.json`

### Synthetic SOAR responder benchmark

The separate ten-run synthetic SOAR benchmark completed **10/10 verified runs**.

| Measurement | Result |
|---|---:|
| Verified runs | 10/10 |
| Mean responder execution | 0.692625 s |
| Maximum responder execution | 0.775812 s |
| Mean synthetic event-to-verified | 0.692646 s |
| Maximum synthetic event-to-verified | 0.775827 s |

Evidence:

`evidence/runtime/soar-ten-run-benchmark-20261125-10of10.json`

This is a synthetic responder benchmark. Its event timestamp is generated at execution time. It is not a native CloudTrail event-to-quarantine measurement and must not be substituted for the native benchmark.

### Live LocalStack drift-mutation tests

The production drift collector and comparison path were exercised against controlled LocalStack API mutations. Each test restored the original configuration and checked recovery to the approved baseline.

| Resource | Controlled mutation | Result |
|---|---|---|
| IAM users | Created an unexpected temporary IAM user | Drift detected; user deleted; inventory restored |
| IAM access keys | Created a temporary user and access key | Drift detected; key and user deleted; inventory restored |
| S3 bucket policy | Added a temporary policy statement | Drift detected; original policy restored |
| S3 encryption | Changed the audit bucket's Bucket Key setting | Drift detected; original configuration restored |
| KMS key policy | Changed a statement identifier without changing permissions | Policy-document drift detected; original policy restored |
| CloudTrail | Disabled log-file validation on the approved trail | Configuration drift detected; setting restored |

These were live API mutation tests against LocalStack, not production AWS tests.

The KMS mutation demonstrates detection of a policy-document change; it does not demonstrate detection of an added dangerous permission.

The CloudTrail mutation changed log-file validation and produced the broader finding `CloudTrail destination, logging, or event-selector drift`. It does not establish detection of every possible trail-target or logging configuration change.

Additional collector-level tests use mocked AWS clients to exercise IAM, KMS, CloudTrail, and S3 API collection behavior. These mocked tests are distinct from the live LocalStack mutations.

### Detection, replay protection, and containment

The detection test suite includes coverage for privilege-escalation and defense-evasion patterns, secret and SSM enumeration, malformed or spoofed identity data, role-session attribution, break-glass handling, multi-hop role chains, event-ID reuse, and benign event sequences.

Replay-protection tests cover replay after cache eviction and process restart, reuse of an event ID with a different payload, event-ledger retention, and legacy-schema behavior.

The SOAR responder is dry-run by default. Execution requires explicit activation. The implementation includes break-glass protections, quarantine verification, and session-revocation policy handling.

### Live quarantine rollback demonstration

A live LocalStack demonstration exercised quarantine and rollback against one uniquely generated, disposable IAM user.

- **25 checks passed; zero failed.**
- Verified quarantine and a non-mutating rollback dry-run.
- Verified the rollback plan targeted only the disposable principal, removed both quarantine policies, and reactivated only the originally active access key.
- Verified restoration of the original access-key states and inline policy.
- Verified audit recording of the operator and reason.
- Verified duplicate rollback rejection without further mutation.
- Verified cleanup and removal of the disposable user.

Evidence:

`evidence/phase2/gapfill/rollback-live-20261127T135152Z.json`

This test does not demonstrate multi-principal or shared role-chain rollback. It is LocalStack validation, not proof of live AWS STS token invalidation.

### Drift-baseline integrity

The current drift-baseline integrity mechanism uses a detached Ed25519 signature rather than the earlier HMAC mechanism.

The signing workflow was tested across two machines:

1. The approved baseline was signed on the Windows signing workstation using the passphrase-protected Ed25519 private key.
2. The detached signature was transferred separately.
3. EC2 verified the signature using the trusted public-key configuration and signer namespace.
4. The Windows and EC2 baseline files were confirmed identical by SHA-256.

A separate tamper test modified a copy of the baseline and confirmed that signature verification rejected it.

The production baseline and its existing production signature were not modified during the cross-machine signing test.

## Important limitations and trust boundaries

- LocalStack IAM policy acceptance and readback do not prove that an already-issued AWS STS token is invalidated as it would be in AWS.
- Authorization-denial timing is separate from event-to-verified quarantine latency.
- Native `cloudtrail:StopLogging` event capture and automated SOAR response for that event are not verified. LocalStack accepted the API call, but the expected native event was not observed through the tested event paths.
- The native benchmark does not establish production AWS performance.
- Compromise of the Windows signing workstation or its privileged accounts could expose or misuse the private signing key.
- EC2 stores the baseline, signature, trusted public-key configuration, and verification code. A privileged attacker able to modify the trusted signer configuration or verification code could bypass local verification.
- Searches of selected EC2 locations did not prove that no duplicate private signing-key copy exists on the host.
- The KMS live mutation changed policy-document metadata, not an authorization grant.
- The CloudTrail live mutation changed log-file validation; it did not verify every possible trail-target or logging configuration mutation.
- LocalStack testing does not replace validation in a controlled AWS account. AWS-specific behavior, permissions, event delivery, and credential revocation semantics require separate real-AWS validation.

## Validation commands

Run commands from the repository root. These commands assume the project virtual environment and LocalStack environment have already been configured.

Full regression suite:

```bash
~/ccpd-venv/bin/python -m pytest -q
```

Detection and adversarial tests:

```bash
~/ccpd-venv/bin/python -m pytest -q tests/test_cloud_control_plane_defense.py
```

Replay-protection focused tests:

```bash
~/ccpd-venv/bin/python -m pytest -q tests/test_sqs_consumer.py -k 'replay_after_cache_eviction or replay_after_restart or same_event_id or event_ledger'
```

IAM drift tests:

```bash
~/ccpd-venv/bin/python -m pytest -q tests/test_drift_reconciler_iam.py
```

KMS drift tests:

```bash
~/ccpd-venv/bin/python -m pytest -q tests/test_drift_reconciler_kms.py
```

Live collector tests:

```bash
~/ccpd-venv/bin/python -m pytest -q tests/test_drift_reconciler_live_collectors.py
```

Terraform/Rego policy verification:

```bash
conftest verify --policy policies
```

Rego deny-rule mutation campaign:

```bash
~/ccpd-venv/bin/python scripts/rego_mutation_check.py
```

Patch whitespace validation:

```bash
git diff --check
```

Native event-time benchmark:

```bash
~/ccpd-venv/bin/python scripts/benchmark_native_eventtime.py --runs 10 --timeout 60 --observation-window 15 --label native-boundary-aligned-20261127
```

Benchmark execution interacts with the configured LocalStack environment and creates runtime evidence. Review the environment and queues before running it again.

## Project report and evidence

The detailed project report is:

`docs/Zero-Trust-Cloud-Control-Plane-Defense-Report.md`

The `evidence/` directory contains benchmark outputs, test artifacts, drift-mutation evidence, and supporting runtime records.

Consult the report for detailed methodology, evidence references, timing definitions, implementation details, and submission status.

This README summarizes recorded results. It does not claim that every Phase 2 evaluation requirement or every real-AWS validation scenario is complete.
