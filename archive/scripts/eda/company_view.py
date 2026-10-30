import json
import sys
from collections import Counter

# Domains that identify a hosting/CDN/ISP provider rather than the business running the service.
INFRA = {
    "incapdns.net", "googleusercontent.com", "amazonaws.com", "cloudfront.net", "imperva.com",
    "akamaitechnologies.com", "btcentralplus.com", "your-server.de", "flyio.net", "spectrum.com",
    "scw.cloud", "contaboserver.net", "t-ipconnect.de", "linodeusercontent.com", "vultrusercontent.com",
    "akamaiedge.net", "cloudflare.com", "azure.com", "cloudapp.net", "bc.googleusercontent.com",
    "hwclouds-dns.com", "aliyun.com", "ovh.net", "ip-addr.es", "comcast.net", "verizon.net",
    "rr.com", "sbcglobal.net", "charter.com", "cox.net", "hinet.net", "kornet.net", "vodafone.com",
}

path = sys.argv[1]
n = 0
with_domain = 0
company_domain = 0
cert_org = Counter()
cert_keys = Counter()
company_domains = Counter()
expired = 0
self_signed = 0
ssl_n = 0
samples = []

for line in open(path, "rb"):
    r = json.loads(line)
    n += 1
    doms = [d for d in (r.get("domains") or [])]
    if doms:
        with_domain += 1
    real = [d for d in doms if d not in INFRA]
    if real:
        company_domain += 1
        company_domains.update(real)
        if len(samples) < 40:
            samples.append((r.get("ip_str"), r.get("port"), real[:2], r.get("org"), r.get("product"),
                            (r.get("location") or {}).get("country_code"), sorted((r.get("vulns") or {}).keys())[:3]))
    s = r.get("ssl") or {}
    if s:
        ssl_n += 1
        c = s.get("cert") or {}
        cert_keys.update(c.keys())
        subj = c.get("subject") or {}
        if subj.get("O"):
            cert_org[subj["O"]] += 1
        if c.get("expired"):
            expired += 1
        if c.get("issuer") == c.get("subject"):
            self_signed += 1

print(f"records={n} with_any_domain={with_domain/n:.1%} with_non_infra_domain={company_domain/n:.1%}")
print(f"distinct non-infra domains: {len(company_domains)}")
print("top non-infra domains:", ", ".join(f"{k}={v}" for k, v in company_domains.most_common(40)))
print(f"\nssl records={ssl_n} expired_cert={expired} self_signed={self_signed}")
print("ssl.cert keys:", dict(cert_keys))
print("top cert subject O:", ", ".join(f"{k}={v}" for k, v in cert_org.most_common(25)))
print("\nsample rows with a non-infra domain (ip, port, domains, org, product, cc, cves):")
for s in samples:
    print("  ", s)
