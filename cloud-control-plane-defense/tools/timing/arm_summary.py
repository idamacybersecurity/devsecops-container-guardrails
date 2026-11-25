import json, sys, statistics as S
print(f'{"arm":34s} {"calls":>5s} {"slow>3s":>7s} {"median":>8s} {"p95":>8s} {"max":>8s}')
for f in sys.argv[1:]:
    d = sorted(json.loads(l)["dur_s"] for l in open(f))
    p95 = d[int(0.95 * (len(d) - 1))]
    name = f.split("/")[-1].replace("probe_", "").replace(".jsonl", "")
    print(f'{name:34s} {len(d):5d} {sum(x > 3 for x in d):7d} {S.median(d)*1000:7.0f}ms {p95*1000:7.0f}ms {d[-1]:7.2f}s')
