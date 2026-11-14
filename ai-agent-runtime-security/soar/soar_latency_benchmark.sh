#!/usr/bin/env bash
# Correlated SOAR latency benchmark: N live quarantine runs on fresh disposable containers.
set -u
N="${1:-10}"
REPO=/home/ubuntu/devsecops-container-guardrails
ROOT="$REPO/ai-agent-runtime-security"
OUT="$ROOT/evidence/soar"
CSV="$OUT/correlated-latency-benchmark.csv"
RAW="$OUT/correlated-latency-benchmark-raw.log"
NAME=ai-agent-correlated-soar

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
cd "$REPO" || exit 1

echo "===== LOAD MONITOR POLICY IF NEEDED ====="
if ! docker exec tetragon tetra tracingpolicy list | grep -q 'ai-agent-workspace-write'; then
  docker cp "$ROOT/tetragon/ai-agent-workspace-write.yaml" tetragon:/tmp/ai-agent-workspace-write.yaml
  docker exec tetragon tetra tracingpolicy add /tmp/ai-agent-workspace-write.yaml
fi
docker exec tetragon tetra tracingpolicy list | grep 'ai-agent-workspace-write' || { echo "Policy not loaded"; exit 1; }

echo "run,container_id,event_time,event_to_termination_s,timing_status,event_to_verified_exit_s,docker_exit_code,docker_finished_at" > "$CSV"
: > "$RAW"

field() { echo "$1" | grep -o "$2=[^ ]*" | head -1 | cut -d= -f2; }

for i in $(seq 1 "$N"); do
  echo "===== RUN $i of $N ====="
  docker rm -f "$NAME" >/dev/null 2>&1
  LOG=$(mktemp)
  python3 -u "$ROOT/soar/correlated_soar_daemon.py" --execute > "$LOG" 2>&1 &
  DPID=$!
  for t in $(seq 1 20); do grep -q 'Connecting to Tetragon' "$LOG" && break; sleep 0.5; done
  sleep 3

  docker run -d --name "$NAME" \
    --network none --user 10001:10001 --read-only --cap-drop ALL \
    --memory 256m --pids-limit 64 --tmpfs /tmp \
    -v "$ROOT/agent/workspace:/workspace" \
    --label role=ai-agent --label security.lab.quarantine=true --label security.lab.role=disposable-agent \
    --entrypoint python ai-agent-sandbox:baseline \
    -c "from pathlib import Path; import time; p=Path('/workspace/output/CORRELATED_SOAR_BENCH_$i'); p.write_text('bench\n'); print('SOAR_PROBE_WRITE_OK', flush=True); time.sleep(300)" >/dev/null

  for t in $(seq 1 60); do grep -q 'QUARANTINED' "$LOG" && break; sleep 0.5; done
  sleep 1
  kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
  { echo "--- run $i ---"; cat "$LOG"; } >> "$RAW"

  LINE=$(grep 'QUARANTINED' "$LOG" | head -1)
  EXITC=$(docker inspect -f '{{.State.ExitCode}}' "$NAME" 2>/dev/null)
  FIN=$(docker inspect -f '{{.State.FinishedAt}}' "$NAME" 2>/dev/null)
  if [ -z "$LINE" ]; then
    echo "$i,NOT_QUARANTINED,,,,,$EXITC,$FIN" >> "$CSV"
    echo "  result: NOT QUARANTINED (see raw log)"
  else
    CID=$(field "$LINE" container_id)
    echo "$i,$CID,$(field "$LINE" event_time),$(field "$LINE" event_to_termination_seconds),$(field "$LINE" termination_timing_status),$(field "$LINE" event_to_verified_exit_seconds),$EXITC,$FIN" >> "$CSV"
    echo "  result: ${CID:0:12} exit=$EXITC termination=$(field "$LINE" event_to_termination_seconds)s verified=$(field "$LINE" event_to_verified_exit_seconds)s"
  fi
  rm -f "$LOG"
  docker rm -f "$NAME" >/dev/null 2>&1
  sleep 2
done

rm -f "$ROOT"/agent/workspace/output/CORRELATED_SOAR_BENCH_* 2>/dev/null

echo
echo "===== SUMMARY ====="
python3 - "$CSV" <<'PY'
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1])))
ok = [r for r in rows if r["container_id"] != "NOT_QUARANTINED"]
print("runs:", len(rows), " quarantined:", len(ok), " exit 137:", sum(r["docker_exit_code"] == "137" for r in ok))
for col in ("event_to_termination_s", "event_to_verified_exit_s"):
    v = []
    for r in ok:
        try: v.append(float(r[col]))
        except ValueError: pass
    if v:
        print(f"{col}: n={len(v)} min={min(v):.4f} median={statistics.median(v):.4f} mean={statistics.mean(v):.4f} max={max(v):.4f}")
PY
echo "CSV: $CSV"
echo "Raw: $RAW"
