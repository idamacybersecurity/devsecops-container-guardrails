# Phase 5 — Deliverable 3: Admission Benchmark Report

## Environment
- Kubernetes: local k3s cluster on WSL2
- Admission control: Kyverno
- Production policy: fail-closed enforcement retained
- Mode C image: Zot mirrored API image
- Image digest: sha256:095346b6f01bb2198b16b113b8b15377815eca84d94d3a3d26a4cc17c6e1317b

## Results

| Measurement | Samples | Successful | Failed | Median (ms) | Min (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Mode C mirrored-image admission dry runs | 5 | 5 | 0 | 5437 | 2770 | 8307 |
| Read-only kubectl client/API baseline | 5 | 5 | 0 | 2877 | 2033 | 4399 |

## Interpretation
All recorded Mode C requests succeeded and pinned the image to the expected digest. Timings are end-to-end PowerShell/WSL/kubectl/API timings, not isolated Kyverno verification latency. The read-only baseline is a comparison point, not a value that can be subtracted to derive exact admission latency.

The measured Mode C median is above the sub-second target. Therefore, the target is not yet demonstrated. These repeated requests may benefit from Kyverno verification caching; they do not constitute an uncached benchmark.

## Limitations and next work
- Mode A/B remote GHCR measurements have been impeded by connectivity from cluster pods to GHCR.
- A full 20-successful-sample-per-mode benchmark and a reliable p95 comparison remain outstanding.
- No production fail-closed policy was weakened for these measurements.

## Evidence files
- P5-08B-Mode-C-Benchmark.csv
- P5-09A-PowerShell-WSL-Kubectl-Baseline.csv
