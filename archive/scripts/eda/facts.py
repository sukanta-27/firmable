import json
import sys
from collections import Counter

path = sys.argv[1]
n = 0
sg = 0
sg_incapsula = 0
cdn_nonweb_probe = 0
cdn_nonweb_probe_http_reply = 0
apache = 0
apache_with_2013_4365 = 0
cve_2013_4365_summary = None
verified = []
ip_ports = Counter()
cloud_provider = Counter()
http_200 = 0
hdr = Counter()
securitytxt = 0
ssl_n = 0
ssl_expired = 0
ssl_tls10 = 0
ssl_sslv3_or_v2 = 0
eol_products = Counter()
remote_access = Counter()
no_country = 0
ipv6 = 0

WEB_PROBES = {"auto", "http", "https", "http-simple-new", "https-simple-new"}
SEC_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")

for line in open(path, "rb"):
    r = json.loads(line)
    n += 1
    tags = set(r.get("tags") or [])
    loc = r.get("location") or {}
    org = r.get("org") or ""
    if loc.get("country_code") == "SG":
        sg += 1
        sg_incapsula += org.startswith("Incapsula")
    if not loc.get("country_code"):
        no_country += 1
    if r.get("ipv6"):
        ipv6 += 1
    module = (r.get("_shodan") or {}).get("module") or ""
    if "cdn" in tags and module not in WEB_PROBES:
        cdn_nonweb_probe += 1
        cdn_nonweb_probe_http_reply += (r.get("data") or "").startswith("HTTP/")
    v = r.get("vulns") or {}
    if r.get("product") == "Apache httpd":
        apache += 1
        if "CVE-2013-4365" in v:
            apache_with_2013_4365 += 1
            cve_2013_4365_summary = cve_2013_4365_summary or v["CVE-2013-4365"].get("summary")
    for cve, x in v.items():
        if (x or {}).get("verified"):
            verified.append((org, r.get("product"), r.get("version"), cve, x.get("cvss")))
    ip_ports[r.get("ip_str") or r.get("ipv6")] += 1
    c = r.get("cloud") or {}
    if c:
        cloud_provider[c.get("provider")] += 1
    h = r.get("http") or {}
    if h.get("status") == 200:
        http_200 += 1
        headers = {k.lower() for k in (h.get("headers") or {})}
        for name in SEC_HEADERS:
            hdr[name] += name in headers
    if h.get("securitytxt"):
        securitytxt += 1
    s = r.get("ssl") or {}
    if s:
        ssl_n += 1
        ssl_expired += bool((s.get("cert") or {}).get("expired"))
        offered = set(s.get("versions") or [])
        ssl_tls10 += "TLSv1" in offered
        ssl_sslv3_or_v2 += bool(offered & {"SSLv3", "SSLv2"})
    if "eol-product" in tags:
        eol_products[r.get("product")] += 1
    if r.get("product") in ("Remote Desktop Protocol", "TeamViewer", "RustDesk", "VNC") or module in ("rdp", "teamviewer", "vnc"):
        remote_access[(r.get("product") or module, "cdn" if "cdn" in tags else "non-cdn")] += 1

print(f"records={n}")
print(f"country_code missing: {no_country}; ipv6 records: {ipv6}")
print(f"SG records={sg}, of which org Incapsula*={sg_incapsula} ({sg_incapsula/sg:.1%})")
print(f"cdn-tagged records probed with a non-web module={cdn_nonweb_probe}, reply starts with 'HTTP/'={cdn_nonweb_probe_http_reply} ({cdn_nonweb_probe_http_reply/cdn_nonweb_probe:.1%})")
print(f"Apache httpd records={apache}, carrying CVE-2013-4365={apache_with_2013_4365} ({apache_with_2013_4365/apache:.1%})")
print(f"CVE-2013-4365 summary in data: {(cve_2013_4365_summary or '')[:200]}")
print(f"verified vuln entries={len(verified)} across records:")
for v in verified:
    print("   ", v)
multi = sum(1 for c in ip_ports.values() if c > 1)
print(f"distinct IPs={len(ip_ports)}; IPs seen on >1 port in sample={multi}; max records for one IP={max(ip_ports.values())}")
print(f"cloud providers: {cloud_provider.most_common(10)}")
print(f"http status-200 records={http_200}; security header present: " + ", ".join(f"{k}={c} ({c/http_200:.1%})" for k, c in hdr.items()))
print(f"records with security.txt={securitytxt}")
print(f"ssl records={ssl_n}; cert expired={ssl_expired} ({ssl_expired/ssl_n:.1%}); offers TLSv1.0={ssl_tls10} ({ssl_tls10/ssl_n:.1%}); offers SSLv3/SSLv2={ssl_sslv3_or_v2}")
print(f"eol-product tagged, by product: {eol_products.most_common(10)}")
print(f"remote access services: {remote_access.most_common()}")
