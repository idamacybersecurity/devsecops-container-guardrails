import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1])]
print(f"{len(rows)} calls, total {sum(r['dur_s'] for r in rows):.2f}s")
print("\n-- 10 slowest --")
for r in sorted(rows, key=lambda r: -r["dur_s"])[:10]:
    print(f"{r['dur_s']:8.3f}s  {r['svc']}.{r['op']}  ok={r['ok']}  pid={r['pid']}")
agg = collections.defaultdict(list)
for r in rows:
    agg[f"{r['svc']}.{r['op']}"].append(r["dur_s"])
print("\n-- per operation (count, mean, max) --")
for k, v in sorted(agg.items(), key=lambda kv: -max(kv[1]))[:15]:
    print(f"{k:40s} n={len(v):4d} mean={sum(v)/len(v):7.3f} max={max(v):7.3f}")
