#!/usr/bin/env bash
# usage: bench-admission.sh <image> <runs> <label>
IMAGE="$1"; RUNS="${2:-5}"; LABEL="${3:-run}"
echo "label,run,exit_code,elapsed_ms,result"
for i in $(seq 1 "$RUNS"); do
  s=$(date +%s%3N)
  out=$(kubectl run "bench-$LABEL-$i" --image="$IMAGE" --dry-run=server -n default --request-timeout=120s 2>&1); rc=$?
  e=$(date +%s%3N)
  echo "$LABEL,$i,$rc,$((e-s)),$(echo "$out" | head -n1 | cut -c1-70 | tr ',' ';')"
done
