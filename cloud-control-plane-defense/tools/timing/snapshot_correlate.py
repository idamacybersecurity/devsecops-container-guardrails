import json, re, sys, datetime as dt
jsonl, logf = sys.argv[1], sys.argv[2]
rows = [json.loads(l) for l in open(jsonl)]
pat = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)\s+WARN.*snapshot save timed out")
warns = []
for l in open(logf, errors="ignore"):
    m = pat.match(l)
    if m:
        warns.append(dt.datetime.fromisoformat(m.group(1)).replace(tzinfo=dt.timezone.utc).timestamp())
slow = [r for r in rows if r["dur_s"] > 3]
fast = [r for r in rows if r["dur_s"] <= 3]
def near(r, w=1.5):
    end = r["start"] + r["dur_s"]
    return [x for x in warns if abs(x - end) <= w]
print(f"snapshot-timeout warnings in log: {len(warns)}")
print(f"slow calls (>3s): {len(slow)}, of which with a warning within 1.5s of call end: {sum(bool(near(r)) for r in slow)}")
print(f"fast calls: {len(fast)}, of which with a warning near their end (chance level): {sum(bool(near(r)) for r in fast)}")
print()
for r in sorted(slow, key=lambda r: r["start"]):
    end = r["start"] + r["dur_s"]
    n = near(r)
    off = f"{min(n, key=lambda x: abs(x-end)) - end:+.2f}s" if n else "none"
    t = dt.datetime.fromtimestamp(end, dt.timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    print(f"  {r['svc']}.{r['op']:20s} {r['dur_s']:7.2f}s  ends {t} UTC  nearest warning offset: {off}")
