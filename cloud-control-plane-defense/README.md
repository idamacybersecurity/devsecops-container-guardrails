# Zero-Trust Cloud Control-Plane Defense

Local, zero-cloud-spend security architecture for detecting control-plane
attacks, attributing multi-hop IAM role assumptions, containing compromised
identities, and reconciling unauthorized infrastructure drift.

## Environment

- Docker and LocalStack for AWS API emulation
- Terraform for infrastructure provisioning and approved configuration
- Conftest / OPA for pre-deployment policy evaluation
- Python 3 and boto3 for detection, response, and drift inspection
- pytest for automated regression and adversarial tests

**Cost boundary:** This project is designed and exercised against LocalStack.
No paid AWS resources are required by the intended execution workflow.

## Components

| Path | Responsibility |
|---|---|
| `terraform/` | Local cloud infrastructure |
| `policies/` | OPA / Rego policy gate |
| `detector/cloud_control_plane_detector.py` | CloudTrail/EventBridge parsing, attribution, and anomaly detection |
| `detector/sqs_consumer.py` | SQS event consumption and alert persistence |
| `soar/cloud_soar_responder.py` | Validated, dry-run-by-default IAM containment |
| `drift/drift_reconciler.py` | Baseline comparison, forensic snapshot, and targeted remediation |
| `tests/` | Automated regression and security tests |
| `scripts/` | Validation and benchmark utilities |
| `evidence/` | Project evidence and forensic artifacts |
| `docs/` | Architecture, policy, and final submission documentation |

## Verified results

- Automated regression suite: **67 passed**.
- Focused break-glass and malformed-event tests: **5 passed**.
- Ten-run SOAR benchmark: **10/10 passed**; mean measured execution latency
  approximately **0.254 seconds**.
- Native CloudTrail evidence and verified containment were obtained for
  `kms:DisableKeyRotation` and `s3:DeleteBucketPolicy`.
- Out-of-band public-ingress and IAM trust drift were injected, detected,
  snapshotted, remediated, and independently read back.

## Important limitations

- LocalStack accepted the `cloudtrail:StopLogging` API call, but no native
  StopLogging event was found through CloudTrail event history, S3 log delivery,
  or EventBridge-to-SQS. A separate benign S3 management-event test also failed
  to arrive through the same native CloudTrail-to-EventBridge path.
- Therefore, native StopLogging event capture and automated SOAR response for
  that specific event are **not verified**.
- LocalStack IAM policy acceptance/readback does not prove that an existing
  STS token is invalidated as it would be in AWS.
- The ten-run benchmark measures the implemented SOAR execution path; it is
  not a full end-to-end CloudTrail-to-verified-quarantine benchmark.
- The drift baseline HMAC key resides on the same host as the baseline, so it
  is not an independent root of trust.

See `docs/Zero-Trust-Cloud-Control-Plane-Defense-Report.md` for the detailed
results, evidence references, limitations, and submission status.
