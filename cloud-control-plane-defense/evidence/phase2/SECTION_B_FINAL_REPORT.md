# Phase 2 — Section B: Performance Investigation and Native Event-Time Verification

**Date:** 2026-11-24
**Baseline Git commit:** `cad3d6652e4057f7b2f5e293fb684739614b1439`
**Environment:** AWS EC2, LocalStack Pro, region `eu-north-1`

## 1. Objective

Investigate intermittent latency in the cloud-control-plane defense event-processing path, determine whether persistence, enforcement, copied state, KMS activity, or scheduled snapshots correlate with the observed stalls, and verify native event-time response using independently checked quarantine outcomes.

The investigation distinguishes API-call latency from end-to-end event verification latency. These are separate measurements and must not be treated as interchangeable.

## 2. Timing instrumentation and baseline

Timing instrumentation was added through `tools/timing/sitecustomize.py` to capture calls made by the main process and subprocesses.

The initial native baseline recorded:
- 10 test runs.
- 10/10 `QUARANTINE_VERIFIED`.
- Zero timeouts.
- 6/10 runs under one second.
- Median end-to-end verification: 0.8585 seconds.
- P90: 23.933 seconds.
- Maximum: 26.581 seconds.
- Three attack API calls exceeded five seconds.

The timing evidence localized significant delays to the LocalStack interaction path rather than establishing that responder execution itself was responsible.

## 3. Hypothesis testing

The investigation tested CPU steal, a fixed ten-second timeout hypothesis, persistence/enforcement interactions, copied state, IAM-user accumulation, KMS key state, and snapshot activity.

### 3.1 CPU and timeout hypotheses

- CPU-steal investigation did not support CPU steal as the explanation for the observed stalls.
- The fixed approximately ten-second timeout hypothesis was not supported by the controlled test.
- Snapshot-save timeout warnings were observed in temporal proximity to slow calls.

These results reject neither every possible host-resource issue nor every timeout-related issue; they only fail to support the specific hypotheses tested.

### 3.2 Persistence and enforcement factorial test

Four test arms examined persistence and enforcement combinations.

Across 968 calls, zero stalls were observed. Under these test conditions, neither persistence nor enforcement alone explained the intermittent stalls.

### 3.3 Copied-state and KMS investigation

- Tests using copied LocalStack state exhibited stalls.
- Removing 106 `ccpd-*` IAM users did not eliminate the stalls.
- A seeded test containing 84 KMS keys pending deletion did not independently reproduce the stalls.
- The original `volume` was preserved; the controlled comparisons used copied state.

The copied-state result indicates that state-dependent behavior deserved further investigation. It does not establish that IAM-user accumulation or pending-deletion KMS keys independently caused the issue.

## 4. Scheduled versus manual snapshot comparison

Two identical copied-state test environments were compared sequentially. Both used persistence and enforcement. The intended difference was snapshot strategy:

- Control: `SNAPSHOT_SAVE_STRATEGY=SCHEDULED`
- Comparison: `SNAPSHOT_SAVE_STRATEGY=MANUAL`

Each arm generated 242 workload calls.

| Measurement | Scheduled | Manual |
|---|---:|---:|
| Calls | 242 | 242 |
| Calls over 3 seconds | 2 | 0 |
| Median | 12.6 ms | 11.7 ms |
| P95 | 71.2 ms | 63.9 ms |
| Maximum | 5.137 s | 0.110 s |

In the scheduled arm, two slow `kms.EnableKeyRotation` calls took approximately 4.404 seconds and 5.137 seconds. Both overlapped snapshot-save intervals of approximately 5.21 and 5.22 seconds. Two snapshot entries were recorded.

The manual arm recorded no snapshot-save entries and no calls over three seconds.

**Interpretation:** This controlled comparison supports an association between scheduled snapshot activity and the observed long calls in this experiment. It does not prove causation: only one run per arm was performed, and the measurements do not isolate every possible interaction within LocalStack.

Both experiment containers were stopped after testing. Their test volumes and evidence were preserved at the time of the experiment; no cleanup of those artifacts is claimed here.

## 5. Isolated native event-time benchmark

A final ten-run native benchmark was executed using a dedicated SQS queue and dedicated EventBridge rule to avoid consuming or purging the main security queue.

Results:
- Runs: 10.
- `QUARANTINE_VERIFIED`: 10/10.
- Timeouts: 0.
- Independent readback checks passed on all ten runs:
  - Deny policy verified.
  - Session policy verified.
  - Access keys inactive.
- Runs under one second: 9/10.
- Attack API calls over five seconds: 0.
- Median end-to-end verification: 0.467 seconds.
- P90: 0.553 seconds.
- Maximum: 18.167 seconds.

One outlier took 18.167 seconds end to end. Its responder execution took approximately 0.274 seconds, placing most of the measured delay before responder completion.

The available timing fields do not distinguish EventBridge delivery delay from SQS receive or detection-processing delay. The precise source of that outlier therefore remains unproven.

### 5.1 Isolation and cleanup

- The dedicated benchmark queue and rule were created for this test.
- The broad main security EventBridge rule was temporarily disabled during the isolated benchmark and subsequently restored.
- The main rule was verified `ENABLED`.
- The benchmark did not purge or consume the main security queue.
- The dedicated queue was verified empty before deletion.
- The dedicated benchmark queue and EventBridge rule were deleted after testing.
- Post-test verification showed 210 visible messages in the main security queue. The benchmark did not consume or purge those messages.

**Operational limitation:** Because the main EventBridge rule was temporarily paused, this experiment does not establish whether events occurring during that pause were missed. No zero-event-loss claim is made.

## 6. Evidence and integrity

The experiment records and supporting outputs are retained under `evidence/phase2/`.

The isolated native benchmark evidence is stored in:

`evidence/phase2/native_isolated_20261124T141949Z/`

Its `SHA256SUMS` manifest was generated and verified successfully. All three checks passed:
- Structured benchmark JSON: `OK`
- Human-readable benchmark output: `OK`
- Findings note: `OK`

The recorded SHA-256 values are:

| File | SHA-256 |
|---|---|
| `cad3d66-native-isolated-20261124T142052Z.json` | `d9e0e87bad77379f54323b96e1a60244ddf8c02965fa377ba90a53768747a38a` |
| `benchmark_output.txt` | `0d9edca3defe78ba01c350ea6e431d72cd33b62abce7c6f30c5a607080827fc7` |
| `findings.md` | `38802f99e115087ee9a6c3b8ed1dd73eb0eb7699c33b5103c81e827558ade087` |

## 7. Conclusions

1. The native response path successfully verified quarantine in all ten isolated benchmark runs, with no timeouts and all independent readback checks passing.
2. The isolated benchmark's median and P90 end-to-end verification times were below one second.
3. One end-to-end outlier remained. Its measured delay occurred predominantly before responder completion; the precise upstream component responsible was not identified.
4. The persistence/enforcement factorial test did not reproduce stalls across 968 calls.
5. The scheduled-versus-manual comparison showed long calls overlapping scheduled snapshot activity, while the manual arm did not reproduce those long calls. This is evidence of an association, not definitive proof of causation.
6. Copied-state behavior remains relevant to the investigation, while the tested IAM-user accumulation and pending-deletion KMS-key hypotheses did not independently explain the stalls.

## 8. Completion status and limitations

The Section B timing, controlled comparisons, native benchmark, cleanup of dedicated benchmark resources, and evidence integrity verification have been performed.

The report does not claim:
- That the exact cause of the 18.167-second outlier is known.
- That scheduled snapshots have been proven to be the sole cause of all observed stalls.
- That events could not have been missed during the temporary pause of the main EventBridge rule.
- That unverified deliverables elsewhere in the capstone are complete.

This report records the tests performed and the conclusions supported by their available evidence.
