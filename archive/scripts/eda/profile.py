import json
import sys
from collections import Counter


def top(counter, n=15):
    return ", ".join(f"{k}={v}" for k, v in counter.most_common(n))


path = sys.argv[1]
n = 0
bad = 0
top_keys = Counter()
module = Counter()
port = Counter()
country = Counter()
org = Counter()
tags = Counter()
product = Counter()
transport = Counter()
has = Counter()
vuln_cves = Counter()
vuln_records = 0
vuln_verified = 0
ssl_versions = Counter()
http_status = Counter()
components = Counter()
waf = Counter()
domains = Counter()
sizes = []
ts_min, ts_max = None, None
ips = set()

for line in open(path, "rb"):
    try:
        r = json.loads(line)
    except Exception:
        bad += 1
        continue
    n += 1
    sizes.append(len(line))
    top_keys.update(r.keys())
    sh = r.get("_shodan") or {}
    module[sh.get("module")] += 1
    port[r.get("port")] += 1
    transport[r.get("transport")] += 1
    country[(r.get("location") or {}).get("country_code")] += 1
    org[r.get("org")] += 1
    tags.update(r.get("tags") or [])
    product[r.get("product")] += 1
    ips.add(r.get("ip_str") or r.get("ipv6"))
    ts = r.get("timestamp")
    if ts:
        ts_min = ts if ts_min is None or ts < ts_min else ts_min
        ts_max = ts if ts_max is None or ts > ts_max else ts_max
    for k in ("http", "ssl", "domains", "hostnames", "vulns", "cpe23", "product", "version", "os"):
        if r.get(k):
            has[k] += 1
    if (r.get("opts") or {}).get("vulns"):
        has["opts.vulns"] += 1
    v = r.get("vulns") or {}
    if v:
        vuln_records += 1
        vuln_cves.update(v.keys())
        if any((x or {}).get("verified") for x in v.values()):
            vuln_verified += 1
    s = r.get("ssl") or {}
    ssl_versions.update(x for x in (s.get("versions") or []) if not x.startswith("-"))
    h = r.get("http") or {}
    if h:
        http_status[h.get("status")] += 1
        components.update((h.get("components") or {}).keys())
        if h.get("waf"):
            waf[h.get("waf")] += 1
    for d in r.get("domains") or []:
        domains[d] += 1

sizes.sort()
print(f"records={n} bad_json={bad} distinct_ips={len(ips)}")
print(f"record bytes: median={sizes[len(sizes)//2]} p95={sizes[int(len(sizes)*.95)]} max={sizes[-1]}")
print(f"timestamp range: {ts_min} .. {ts_max}")
print(f"\nTOP-LEVEL KEYS (share of records):")
for k, c in top_keys.most_common():
    print(f"  {k:<22} {c/n:6.1%}")
print(f"\nhas-field: " + ", ".join(f"{k}={c/n:.1%}" for k, c in has.most_common()))
print(f"\nmodule:    {top(module, 25)}")
print(f"\nport:      {top(port, 25)}")
print(f"\ntransport: {top(transport)}")
print(f"\ncountry:   {top(country, 20)}")
print(f"\norg:       {top(org, 20)}")
print(f"\nproduct:   {top(product, 25)}")
print(f"\ntags:      {top(tags, 20)}")
print(f"\nhttp status: {top(http_status, 10)}")
print(f"\nhttp components: {top(components, 30)}")
print(f"\nwaf:       {top(waf, 10)}")
print(f"\nssl versions offered: {top(ssl_versions)}")
print(f"\nrecords with vulns: {vuln_records} ({vuln_records/n:.1%}); with a verified vuln: {vuln_verified}")
print(f"distinct CVEs: {len(vuln_cves)}; top: {top(vuln_cves, 15)}")
print(f"\ndistinct domains: {len(domains)}; top: {top(domains, 15)}")
