import json, sys, datetime as dt, statistics as S
D = sys.argv[1]
rows = [json.loads(l) for l in open(f"{D}/boto_timing.jsonl")]
vm = []
for l in open(f"{D}/vmstat.log"):
    f = l.split()
    if len(f) == 20 and f[0].isdigit():
        t = dt.datetime.strptime(f[18] + " " + f[19], "%Y-%m-%d %H:%M:%S") \
              .replace(tzinfo=dt.timezone.utc).timestamp()
        vm.append((t, int(f[12]), int(f[15]), int(f[16])))   # t, us, wa, st
sts = [v[3] for v in vm]
print(f"vmstat samples: {len(vm)}  steal mean={S.mean(sts):.1f}%  "
      f"max={max(sts)}%  samples with steal>10%: {sum(s>10 for s in sts)}/{len(sts)}")
gaps = [(vm[i+1][0]-vm[i][0], vm[i][0]) for i in range(len(vm)-1)]
big = [g for g in gaps if g[0] > 1.5]
print(f"vmstat gaps >1.5s (whole-VM freeze if present): {len(big)}  max={max(g[0] for g in gaps):.1f}s")

def window(a, b):
    w = [v for v in vm if a-1 <= v[0] <= b+1]
    return (S.mean(v[3] for v in w), max(v[3] for v in w)) if w else (None, None)

fast = [r for r in rows if r["dur_s"] < 1]
fm = S.mean(window(r["start"], r["start"]+r["dur_s"])[0] or 0 for r in fast[:100])
print(f"\nmean steal during 100 fast calls: {fm:.1f}%")
print("\nslow calls (>3s):")
for r in sorted(rows, key=lambda r: r["start"]):
    if r["dur_s"] > 3:
        m, mx = window(r["start"], r["start"] + r["dur_s"])
        t = dt.datetime.fromtimestamp(r["start"], dt.timezone.utc).strftime("%H:%M:%S")
        print(f"  {t} UTC  {r['svc']}.{r['op']:22s} {r['dur_s']:7.2f}s  pid={r['pid']}  "
              f"steal mean={m:.1f}% max={mx}%")
