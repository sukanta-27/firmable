import json
import sys
from collections import Counter

path = sys.argv[1]


def brief(r, data_chars=300):
    v = r.get("vulns") or {}
    vulns = {k: {"cvss": x.get("cvss"), "verified": x.get("verified")} for k, x in list(v.items())[:4]}
    c = (r.get("ssl") or {}).get("cert") or {}
    return {
        "ip": r.get("ip_str"), "port": r.get("port"), "module": (r.get("_shodan") or {}).get("module"),
        "org": r.get("org"), "asn": r.get("asn"), "country": (r.get("location") or {}).get("country_code"),
        "hostnames": (r.get("hostnames") or [])[:3], "domains": (r.get("domains") or [])[:3],
        "product": r.get("product"), "version": r.get("version"), "tags": r.get("tags"),
        "cpe23": (r.get("cpe23") or [])[:3],
        "vulns(first4)": vulns or None, "n_vulns": len(v) or None,
        "cert": {"subject": c.get("subject"), "expires": c.get("expires"), "expired": c.get("expired")} if c else None,
        "http_title": (r.get("http") or {}).get("title"),
        "data": (r.get("data") or "")[:data_chars],
    }


picks = {
    "company-owned IP (org is the business itself)": lambda r: r.get("org") == "Wal-Mart Stores, Inc.",
    "exposed database": lambda r: r.get("product") in ("MongoDB", "MySQL") and r.get("domains"),
    "known-vulnerable web server": lambda r: len(r.get("vulns") or {}) >= 3 and "honeypot" not in (r.get("tags") or []),
    "expired TLS cert on a named host": lambda r: ((r.get("ssl") or {}).get("cert") or {}).get("expired") and r.get("hostnames"),
    "end-of-life product": lambda r: "eol-product" in (r.get("tags") or []),
    "exposed remote access (RDP/RustDesk/VNC)": lambda r: r.get("product") in ("RustDesk", "Remote Desktop Protocol") or "vnc" in r or "rdp_encryption" in r,
    "honeypot (decoy - must be filtered)": lambda r: "honeypot" in (r.get("tags") or []),
    "malware C2 detected (RAT)": lambda r: (r.get("_shodan") or {}).get("module", "").endswith("-rat"),
    "industrial control system (tank gauge)": lambda r: (r.get("_shodan") or {}).get("module") == "automated-tank-gauge",
    "VPN / firewall appliance": lambda r: "vpn" in (r.get("tags") or []) and r.get("product"),
}

found = {}
honeypot_cve_counts = Counter()
nonhoneypot_cve_counts = Counter()
for line in open(path, "rb"):
    r = json.loads(line)
    n = len(r.get("vulns") or {})
    if n:
        (honeypot_cve_counts if "honeypot" in (r.get("tags") or []) else nonhoneypot_cve_counts)[n] += 1
    for label, pred in picks.items():
        if label not in found:
            try:
                if pred(r):
                    found[label] = r
            except Exception:
                pass

for label in picks:
    print(f"\n===== {label} =====")
    if label in found:
        print(json.dumps(brief(found[label]), indent=1, default=str, ensure_ascii=False))
    else:
        print("  (none in sample)")

print("\nvuln-count distribution, honeypot-tagged:", honeypot_cve_counts.most_common(5))
print("vuln-count distribution, not tagged:   ", nonhoneypot_cve_counts.most_common(8))
