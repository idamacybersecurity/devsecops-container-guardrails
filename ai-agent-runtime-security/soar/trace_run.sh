cd /home/ubuntu/devsecops-container-guardrails/ai-agent-runtime-security || exit 1
OUT=evidence/soar/unbroken-trace
docker rm -f ai-agent-correlated-soar >/dev/null 2>&1
timeout 20 docker exec tetragon tetra getevents --policy-names ai-agent-workspace-write -o json > $OUT-tetragon-events.jsonl 2>&1 &
TP=$!
python3 -u soar/correlated_soar_daemon.py --execute > $OUT-soar-daemon.log 2>&1 &
DP=$!
sleep 5
docker run -d --name ai-agent-correlated-soar --network none --user 10001:10001 --read-only --cap-drop ALL --memory 256m --pids-limit 64 --tmpfs /tmp -v "$PWD/agent/workspace:/workspace" --label role=ai-agent --label security.lab.quarantine=true --label security.lab.role=disposable-agent --entrypoint python ai-agent-sandbox:baseline -c "from pathlib import Path; import time; p=Path('/workspace/output/TRACE_PROBE'); p.write_text('trace\n'); print('SOAR_PROBE_WRITE_OK', flush=True); time.sleep(300)" > $OUT-container-start.txt
sleep 8
kill $DP 2>/dev/null
wait $TP 2>/dev/null
docker inspect -f 'ID={{.Id}} Status={{.State.Status}} ExitCode={{.State.ExitCode}} FinishedAt={{.State.FinishedAt}}' ai-agent-correlated-soar | tee $OUT-docker-inspect.txt
echo "--- SOAR DAEMON ---"; cat $OUT-soar-daemon.log
echo "--- TETRAGON EVENT CONTAINER FIELD ---"; grep -o '"docker":"[^"]*"' $OUT-tetragon-events.jsonl | sort -u
docker rm -f ai-agent-correlated-soar >/dev/null 2>&1
rm -f agent/workspace/output/TRACE_PROBE
