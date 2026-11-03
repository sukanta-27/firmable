# Term sheet: what the scan fields mean for prospecting

Every number comes from `archive/scripts/analysis/08_terms.sql`, run on `archive/data/flat/main/*.parquet` (the 2026-10-26 file). Signal definitions are in `archive/scripts/analysis/views.sql`.

Counts are banner records, not companies. "Other" means records not tagged `cdn`, `cloud` or `honeypot`: 4,807,091 records on 3,229,866 IPs. Honeypot records are excluded throughout.

## The three findings that change how to score

1. **Only `verified` vulnerabilities are evidence.** The three biggest KEV CVEs account for 301,438 record–CVE rows and none are verified. They are assumed from nginx and Apache version strings.
2. **CDN records describe the CDN, not the customer.** 86% of WAF records (1,313,972 of 1,520,767) and 77% of PQC records (271,362 of 350,916) are on CDN IPs.
3. **High CVSS and high EPSS describe the CVE, not the host.** 225,104 records carry a CVSS ≥ 9 CVE and 357,056 carry an EPSS ≥ 0.5 CVE. Either is too many to be a lead list.

## Source and ownership

| Term | In your data | What it means for prospecting |
|---|---|---|
| Banner | 14,608,407 records on 4,992,440 IPs | You sell to companies, so every signal has to be rolled up from records to a company. |
| Tags / buckets | cdn 5,862,834 · cloud 3,688,043 · honeypot 250,439 · other 4,807,091 | Exposure signals only mean something in "other", and partly in "cloud". Drop honeypots. |
| `org` / `isp` | 42,600 ASNs. `org` ≠ `isp` on 3,634,024 records. | `org` is usually the hoster or carrier, so it can't name the prospect on its own. `docs/eda/blind-analysis.md` §3 measures this. |
| Hostnames / domains | 10,824,898 records (74%) have at least one | The main route to a company name. Reverse-DNS names set by ISPs (`1-2-3-4.isp.net`) are mixed in and must be filtered (`infra_dom` in `views.sql`). |
| SNI | 739,925 records were scanned by website name (`sni_hostname`) | The scan targeted that site, so the record belongs to it. |
| CPE | 3,054,577 records | Product and version identity. It feeds the version-assumed CVE list, so the CVEs inherit its weaknesses (inferred). |

## Vulnerability fields

| Term | In your data | What it means for prospecting |
|---|---|---|
| CVE | 20,988,468 record–CVE rows on 467,424 records (3.2% of records), 11,064 distinct IDs. Two IDs are Microsoft bulletin numbers, not CVEs: `MS15-034` (579 rows) and `MS17-010` (13 rows). Records with any CVE have a median of 11, p90 128, max 1,000. | A CVE count measures how old the software version is, not risk. Don't rank by it. |
| CVSS | Rows by version: v2.0 3,859,869 · v3.0 16,687,512 · v4.0 441,087. No nulls. | Versions are mixed, and scores from different versions aren't strictly comparable. Use only as a tie-breaker among verified flaws. |
| EPSS | Matches FIRST's 2026-10-27 feed (`data/external/`, model `v2026.06.15`): 11,062 CVEs joined, correlation 0.99, 29 differ by more than 0.1. | The embedded value can be trusted. For a fresh score, join the daily FIRST file instead of re-scanning. |
| KEV | 199 KEV CVEs on 370,460 rows. Against CISA's 2026-10-27 catalog (1,760 entries), 197 agree, 2 are Shodan-only and 2 are catalog-only. Top three: CVE-2023-44487 on 173,523 rows (169,354 nginx), CVE-2024-38475 on 77,237 (72,778 Apache), CVE-2021-40438 on 50,678. **0 verified among them.** | A KEV flag alone means "this version once had an exploited flaw". Join the live catalog to catch CVEs added on scan day. |
| Ransomware use | 58 CVEs marked `Known`, matching the catalog. 54,792 records. | Same caveat as KEV: assumed from version unless verified. It's a strong talking point only on verified flaws. |
| `verified` | 6,111 rows on 4,808 records, 36 distinct IDs. **Verified and KEV: 2,086 records**, of which 1,966 are in "other" on 1,872 IPs. | **The core "needs help now" signal.** It is rare, confirmed by test, and mostly remote takeover. |
| Top verified IDs | CVE-2018-18441 D-Link camera leak 1,061 (not KEV) · SMBGhost 1,038 · FREAK 942 · Logjam 704 · DrayTek CVE-2022-32548 637 · MS15-034 579 and CVE-2015-1635 574 (same flaw, two IDs; overlap not checked) · BlueKeep 198 · Heartbleed 160 · Jenkins CVE-2024-23897 50 | Weight by consequence. SMBGhost, BlueKeep, DrayTek and MS15-034 are takeovers. FREAK and Logjam need an attacker in the network path. The D-Link leak is an information leak. |
| Heartbleed test | Shodan tested 926,405 records and 160 failed. CVE-2014-0160 is attached to 881 records, of which 160 are verified. Of the 721 unverified, 89 were tested and came back `SAFE` and 626 were never tested. | A worked example of assumed vs verified: the version-based flag is contradicted by Shodan's own test on 89 records and untested on 626. |

## Encryption and certificates

| Term | In your data | What it means for prospecting |
|---|---|---|
| TLS 1.0/1.1 accepted | 134,295 records (43,431 other) | Common hygiene gap, weak alone. A version prefixed with `-` means disabled. **358,519 TLS records have an empty version list** (inferred: versions not probed), so absence isn't proof it's off. |
| SSLv2/v3 accepted | 4,039 records (3,281 other) | Rarer and older. A stronger hygiene signal than TLS 1.0. |
| Expired certificate | 53,762 records (32,829 other) | Visible neglect. Count it per company, not per record. |
| Self-signed certificate | 132,202 records (97,162 other) | Normal on device admin pages, so it's weak alone (inferred). |
| `ssl_pubkey_type` | `dsa` on 213,332 records, of which 202,923 are signed with ECDSA | The label means ECDSA (a modern key) in most cases. **Don't use it as a weak-crypto signal.** |
| JARM / JA3S / HASSH | JARM: 8,436 distinct values on 990,592 TLS records. JA3S: 846 distinct. HASSH: 96,279 records, 2,705 distinct. | Not a need signal. Useful for grouping one company's servers by build, or matching known attacker servers. |
| PQC | 350,916 records, 271,362 on CDN | Mostly reflects the CDN's settings, not the customer's maturity. |

## Website protections (signs of maturity)

| Term | In your data | What it means for prospecting |
|---|---|---|
| WAF | 1,520,767 records, 1,313,972 on CDN, 78,875 other | Mostly reflects the CDN. On its own IPs it suggests the company already buys security. |
| HSTS / CSP | HSTS 148,101 · CSP 129,936 (counted on HTTP 200 responses: 1,039,924) | Signs of a maintained website. A small negative weight at most. |
| security.txt | 8,327 records (5,025 other) | A company with a disclosure contact has a security owner, which may mean a buyer. |

## Exposed services

| Term | In your data (definition in `views.sql`) | What it means for prospecting |
|---|---|---|
| RDP | 27,671 records (22,826 other) | A remote desktop open to the internet. Common, and real when it is the company's own IP. |
| RDP without NLA | 1,233 (996 other). RDP whose offered protocols don't include CredSSP. | A stronger signal: no login stands between the internet and the session. |
| SMB / SMBv1 / anonymous SMB | 2,719 / 962 / 440 | Windows file sharing should never face the internet. SMBv1 or anonymous access is strong. |
| VNC / VNC with no auth | 4,913 / 10 | No-auth is critical but almost nonexistent here. |
| Telnet | 3,863 (port 23/2323 or a login prompt in the banner) | Passwords cross the internet in clear text. |
| FTP / anonymous FTP | 20,288 / 997 | Anonymous access can be intentional, such as a public download mirror (inferred). Check before using it. |
| IPMI / iLO / VMware management | 710 | Server management exposed. It has an unpatched design flaw, so it's strong when attributable. |
| EOL product / OS | 244,327 (167,961 other) / 6,036 | Too common to rank alone. Use it as a count per company. |
| Compromise tags (`c2`, `compromised`, `malware`, `doublepulsar`, Cobalt Strike) | 115 (84 other) | Already breached, or a red team. An incident-response conversation, and it needs a human check before outreach. |
