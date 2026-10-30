import json
import sys
from collections import Counter

path = sys.argv[1]
n = 0
cdn_or_cloud = 0
cdn_cloud_or_honeypot = 0
cluster_2013 = Counter()
cluster_93546 = Counter()
verified = []
module_on_cdn = Counter()
module_off_cdn = Counter()
cves_on_cdn = 0
cves_total = 0

for line in open(path, "rb"):
    r = json.loads(line)
    n += 1
    tags = set(r.get("tags") or [])
    infra = bool(tags & {"cdn", "cloud"})
    cdn_or_cloud += infra
    cdn_cloud_or_honeypot += bool(infra or "honeypot" in tags)
    mod = (r.get("_shodan") or {}).get("module")
    (module_on_cdn if "cdn" in tags else module_off_cdn)[mod] += 1
    v = r.get("vulns") or {}
    if v:
        cves_total += 1
        cves_on_cdn += "cdn" in tags
    key = (r.get("product"), r.get("version"), "honeypot" in tags)
    if "CVE-2013-4365" in v:
        cluster_2013[key] += 1
    if "CVE-2026-93546" in v:
        cluster_93546[key] += 1
    for cve, x in v.items():
        if (x or {}).get("verified") and len(verified) < 6:
            verified.append((r.get("ip_str"), r.get("port"), r.get("org"), r.get("product"), r.get("version"),
                             cve, x.get("cvss"), (x.get("summary") or "")[:110]))

print(f"records={n}")
print(f"tagged cdn or cloud: {cdn_or_cloud/n:.1%}; cdn/cloud/honeypot: {cdn_cloud_or_honeypot/n:.1%}")
print(f"records with CVEs that sit on a CDN IP: {cves_on_cdn}/{cves_total}")
print("\nCVE-2013-4365 cluster -> (product, version, honeypot):", cluster_2013.most_common(5))
print("CVE-2026-93546 cluster -> (product, version, honeypot):", cluster_93546.most_common(5))
print("\nprobe modules on CDN IPs:     ", module_on_cdn.most_common(8))
print("probe modules on non-CDN IPs: ", module_off_cdn.most_common(12))
print("\nverified vulns (ip, port, org, product, version, cve, cvss, summary):")
for v in verified:
    print("  ", v)
