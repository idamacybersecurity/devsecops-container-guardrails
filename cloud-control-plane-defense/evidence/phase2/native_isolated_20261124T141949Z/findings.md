# Isolated Native Event-Time Benchmark

Date: 2026-11-24
Baseline commit: cad3d6652e4057f7b2f5e293fb684739614b1439

## Test isolation
- Used a dedicated SQS queue and dedicated EventBridge rule.
- Temporarily disabled the broad main security EventBridge rule during the isolated benchmark.
- Verified that the main security rule was restored to ENABLED after the benchmark.
- The benchmark did not purge or consume the main security queue.
- The dedicated benchmark queue was empty after testing and was subsequently deleted.
- The dedicated benchmark EventBridge rule and queue were deleted after testing.

## Results
- Runs: 10
- QUARANTINE_VERIFIED: 10/10
- Timeouts: 0
- Independent readback checks: passed on all 10 runs
- Runs under 1 second: 9/10
- Attack API calls over 5 seconds: 0
- Median end-to-end verification: 0.467 seconds
- P90 end-to-end verification: 0.553 seconds
- Maximum end-to-end verification: 18.167 seconds

## Outlier analysis
One run took 18.167 seconds end to end. In that run:
- Responder execution: approximately 0.274 seconds.
- Event-to-verification time: approximately 18.168 seconds.

This places the measured delay before responder completion. The available measurements do not distinguish EventBridge delivery delay from SQS receive or detection-processing delay. Further instrumentation would be required to identify the precise cause.

## Operational caveat
The main security EventBridge rule was briefly disabled to isolate benchmark traffic. It was restored and verified ENABLED. The main security queue contained 210 visible messages during post-test verification. The benchmark did not consume or purge those messages. This test does not establish whether events occurring during the temporary rule pause were missed.

## Evidence files
- benchmark_output.txt: human-readable benchmark output
- cad3d66-native-isolated-20261124T142052Z.json: structured per-run results
