# Patterns in the full file

**Date:** 2026-10-28
**Input:** `data/raw/b2_download_file_by_id` (the whole file, 14,608,407 records), not a sample.
**Previous step:** [`initial.md`](initial.md) profiled a 1-in-400 sample. Every number here supersedes the sample estimates.

Every table below is the output of a script in `archive/scripts/analysis/` run against the Parquet produced by `archive/scripts/ingest/flatten_duckdb.py`. Where a judgment was made by hand it says so and gives the sample size.

---

## Headline

1. **One flatten, then everything is seconds.** The 114 GiB file parses into 2.5 GB of Parquet in 72 s. Every analysis query after that runs in 2 to 12 s on a laptop. Details in section 1.
2. **Two thirds of the file is not a company's own server.** CDN edges, cloud provider ranges and honeypots are 67% of records. Of the remaining 4.8M records, 76% sit on ISP, hosting or placeholder ranges where the org string is not the business. Section 2.
3. **Company attribution v1 covers 25% of non-CDN records (808k IPs, 333k companies).** Measured precision per route ranges from 25/25 (SNI, certificate) down to 17/25 (keyword rule on the org string). Section 3.
4. **The CVE field is mostly a version table, but 2,084 records carry a verified, known-exploited, remotely exploitable flaw.** SMBGhost, MS15-034, BlueKeep, Heartbleed, IIS 6 WebDAV, Jenkins. That is the one signal that is rare, verifiable from the banner, severe and attributable. Section 6.
5. **Five rules looked like signals and were artifacts.** Probe modules on CDN IPs, the `medical` tag, PLCs on web-hosting IPs, the `telnet` object on non-telnet ports, and "Redis present". Section 7.

---

## 1. How the file was analysed

### Decision

Flatten the NDJSON once into two Parquet tables with DuckDB, then query the Parquet. The raw file is never decompressed to disk.

| Step | Measured |
|---|---|
| `zstd -dc` alone, first 8 GiB | 3.8 s, about 2.3 GB/s. Decompression is not the bottleneck |
| DuckDB flatten of the 312 MB sample (36,522 records) | 0.3 s cold, 0.2 s warm, 12 threads |
| ClickHouse-local flatten of the same sample, same columns | 0.78 s |
| **Full file flatten, DuckDB** | **58.0 s** for `banners.parquet` (2,401 MB, 266 columns), 14.1 s for `vulns.parquet` (133 MB, 20,988,468 rows). 1 min 12 s wall |
| Row count check | 14,608,407 Parquet rows = 14,608,407 lines (`wc -l`) = 14,608,407 lines starting with `{` |
| Typical analysis query over all 14.6M rows | 2 to 12 s (`q.py` prints the time) |

ClickHouse was rejected for a second reason: a `JSONAsString` key census over the full file returned 13,850,743 records, 5.2% short of the true count, with no error. The cause was not investigated.

### Three things that bit, and the fix

| Problem | Evidence | Fix |
|---|---|---|
| DuckDB aborts the whole run on a type mismatch under explicit `columns` | `Failed to cast value to numerical` on `ssl.cert.serial` (int or float) | Fields with unstable types are declared `JSON` and parsed at query time |
| DuckDB rejects a lone UTF-16 surrogate escape that Python accepts | `Malformed JSON ... no low surrogate` | `ignore_errors=true`. It does **not** skip the line: it keeps an all-NULL row. Exactly 1 of 14,608,407 rows is hollow (`rec_id IS NULL`) |
| `count_if()` returns NULL, not 0, when every input is NULL, and `least(NULL, 3)` is 3 | First ranking gave every company a near-maximum score | `count(*) FILTER (WHERE ...)` everywhere |

### What the Parquet holds

Every record field the analysis used, plus the 163 protocol-specific objects Shodan attaches at the top level (a full-file census found 163, the sample had shown 48). Those are kept as raw JSON text so a new field inside one cannot break ingestion. `http.html` and the raw banner are truncated to 4,000 and 3,000 characters; their full lengths are stored.

### Shape for production

One file arrives, one `flatten_duckdb.py` run, one Parquet partition. Labels and rules (`archive/labels/*.csv`, `views.sql`) are tables, so re-scoring is a query, not a re-parse. A 114 GiB file is 72 s of CPU, so hundreds of files a month is hours, not days.

### Reproduce

```sh
uv venv .venv && uv pip install -p .venv/bin/python duckdb
.venv/bin/python -I archive/scripts/ingest/flatten_duckdb.py data/raw/b2_download_file_by_id archive/data/flat/main --compression zstd --ignore-errors
curl -sSL -o data/external/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -sSL -o data/external/epss_scores-current.csv.gz https://epss.cyentia.com/epss_scores-current.csv.gz
for f in 00_overview 01_owner_inputs 02_signals_by_bucket 03_vulns 04_labelling_inputs 05_attribution 05b_handcheck 06_company 07_glaring_examples; do
  .venv/bin/python -I archive/scripts/analysis/q.py archive/scripts/analysis/$f.sql
done
```

`05_attribution` must run before `06_company` and `07_glaring_examples` (it writes `archive/data/work/attr.parquet`).

---

## 2. What the file is, and who owns the IPs

### The file (`00_overview.sql`)

| Property | Value |
|---|---|
| Records | 14,608,407 on 4,992,440 distinct IPs (312,591 IPv6 records) |
| Time window | 2026-10-25 18:13:32 to 2026-10-26 13:06:06, about 19 h |
| Transport | tcp 14,144,506 · udp 463,900 |
| Top ports | 80 (14.8%) · 443 (5.2%) · 2087 (2.0%) · 161 · 8085 · 500 · 7547 · 9000 · 22 · 3389 (48,774) |
| Probe module | `auto` 52.2% · `http` 15.0% · `http-simple-new` 8.1% · `https` 5.6% |
| Country | US 37.7% · SG 30.6% · CN 5.6% · GB 3.0% · DE 2.9% |
| Org | Incapsula 31.9% (133,382 IPs) · Google LLC 21.7% (669,046 IPs) · Cloudflare 3.8% |
| Has `http` / `ssl` / `vulns` | 4,311,673 / 990,592 / 467,424 |
| Has a domain | 10,824,898 (74.1%) |
| SNI-targeted scan (`_shodan.options.hostname`) | 739,925 |
| Any protocol object | 613,749 |

**Records per IP is bimodal.** 3,689,366 IPs have one record. 73,995 IPs have more than 50 records each and together hold 6,125,038 records (41.9% of the file). An IP answering on 50+ ports is a CDN edge, a honeypot, or a firewall that accepts anything.

### Four buckets by tag (`views.sql`, `01_owner_inputs.sql`)

| Bucket | Records | Share | Distinct IPs |
|---|---|---|---|
| `cdn` (tag) | 5,862,834 | 40.1% | 556,732 |
| `cloud` (tag, not cdn) | 3,688,043 | 25.3% | 1,121,544 |
| `honeypot` (tag) | 250,439 | 1.7% | 90,476 |
| **`other`** | **4,807,091** | **32.9%** | **3,229,866** |

Even inside `other`, 2,230 IPs with more than 50 records hold 337,603 records. Examples by org: Bitly (182 IPs, 85 ports each), Scaleway (170), Egnyte (164), Walmart (94), Fiserv (81). These answer every probe and inherit the CDN artifact problem.

### Owner class of the `other` bucket (`05_attribution.sql`)

Each org string was classified. The top 600 org strings were labelled by the Claude session that wrote this analysis, not checked by a person (`archive/labels/org_class.csv`, 74% of `other` records); the remaining 82,000 org strings fall through keyword rules.

| Owner class | Records | IPs | Distinct orgs | What it means for attribution |
|---|---|---|---|---|
| hosting | 1,744,824 | 1,015,089 | 4,575 | Org is the hoster. Customer must come from domain, certificate or SNI |
| isp | 1,642,153 | 1,273,662 | 22,950 | Org is the carrier. Mostly consumer and SMB lines |
| enterprise (rule) | 557,873 | 456,029 | 46,986 | Org string looks like a company. Precision 17/25, see section 3 |
| placeholder | 328,027 | 287,585 | 4,590 | "IP pools", "Private Customer", "End User Organization", "Customers", "Dynamic IP Addresses" |
| cdn (untagged) | 159,783 | 45,887 | 79 | Meteverse, CDNetworks, 20i anycast, APNIC 1.1.1.1 space |
| enterprise (labelled) | 90,903 | 15,648 | 15 | Walmart, Broadcom, Equifax, NYMEX, KeyBank, Home Depot, Apple, Fiserv, Cellnet, TGS, Yandex, King, Pertamina, Agencia Estado, Board of Trade Clearing |
| saas | 80,309 | 19,605 | 23 | Salesforce, ServiceNow, Shopify, Bitly, Egnyte, Zendesk, Adyen, GitHub, Medidata, Adobe, Atlassian, Appspace |
| proxy farm | 77,983 | 59,028 | 18 | SOCKS5 + Grafana + InfluxDB on every IP, under stale WHOIS names such as "TELUS Communications Inc", "Frontier Communications", "Aviation RE LLC" |
| edu | 53,310 | 29,764 | 2,625 | Universities, NRENs |
| secvendor | 48,366 | 18,064 | 5 | Palo Alto Networks, Zscaler, Proofpoint, Sucuri, Meraki. Not prospects |
| gov | 11,080 | 6,942 | 1,085 | |
| parking | 8,380 | 90 | 3 | Confluence Networks, ParkLogic, SEDO |
| vpn exit | 4,100 | 2,473 | 2 | Mullvad, Surfshark via Cyberzone |

**The enterprises are in the long tail, not the head.** The top 100 org strings in `other` cover 54.9% of its records and are almost all telcos and hosters. Hand-labelled enterprises are 15 org strings. The 46,986 rule-classified strings average under 10 IPs each.

**`org != isp` is a usable signal of a customer-assigned range.** It holds for 97% of labelled enterprise records, 95% of saas, 57% of rule-enterprise, 44% of hosting and 49% of isp.

---

## 3. Company attribution v1 (`05_attribution.sql`)

### Routes, in precedence order

| Route | Rule | Records | IPs | Companies | Precision (n=25, by hand) |
|---|---|---|---|---|---|
| `org_label` | Hand-labelled enterprise / saas / edu / gov / secvendor org | 283,968 | 90,023 | 3,741 | by construction |
| `sni` | Shodan scanned the IP by hostname; registrable domain of that hostname | 514,859 | 80,916 | 55,036 | 25/25 |
| `cert_o` | TLS certificate subject O, after removing vendor defaults and placeholders | 63,688 | 53,317 | 17,572 | 25/25 |
| `domain` | First domain on the record that is not infrastructure | 542,850 | 430,059 | 247,897 | 19/25 |
| `org_rule` | Keyword rules say the org string is not isp/hosting/cdn/placeholder | 408,729 | 344,840 | 37,268 | 17/25 |
| `ntlm` | NTLM `dns_domain_name` leaked by RDP/IIS/WinRM, public TLD | 1,047 | 861 | 702 | 23/25 |
| `ntlm_ad` | Same, `.local` and other private TLDs | 772 | 673 | 634 | not checked |

Precision was judged from `05b_handcheck.sql` (25 records per route, deterministic sample) using org, domains, SNI, certificate and page title. "Correct" means the key names the business that runs the service, not its carrier or hoster. The samples are small; treat the numbers as ±15 points.

### What "infrastructure domain" means

An `infra_dom` table of 7,012 domains is excluded from the `domain` and `sni` routes. It holds 6,687 reverse-DNS domains, detected because at least half their hostnames contain an IP-like digit pattern (`179-125-1-1.embratel.net.br`), 257 AI-drafted labels (`archive/labels/domain_class.csv`), and the dominant domain of any ISP or hoster org. Two regex lists are excluded on top: dynamic-DNS providers and hosting keywords (`host`, `cloud`, `vps`, `^as\d+\.`, `^ip-\d+`). The remaining domain-route errors in the hand-check are small ISPs and hosters whose names carry no such token (`e-kei.pl`, `melsa.net.id`, `troianet.com.br`).

### Coverage

| Bucket | Records attributed | IPs attributed |
|---|---|---|
| `other` | 1,201,254 of 4,807,091 (25.0%) | 808,451 of 3,229,866 (25.0%) |
| `cloud` | 170,487 (4.6%) | 86,795 of 1,121,544 |
| `cdn` | 439,800 (7.5%), almost all via SNI | 95,378 |

| Companies (other + cloud) | 333,230 |
|---|---|
| with exactly 1 IP | 271,369 |
| 2 to 5 IPs | 46,504 |
| 6 to 50 IPs | 13,459 |
| more than 50 IPs | 1,898 |

### What is not attributable, and why

- **Hosting and ISP ranges without a company domain**: 93% of hosting records and 92% of ISP records. A DrayTek router on a BT business line, a Dahua DVR on a Comcast line, a Hetzner box with only `your-server.de` reverse DNS. These carry most of the exposure signals in section 5 and almost none of the attribution.
- **Standalone Windows hosts.** 13,723 of 25,053 NTLM-leaking records in `other` report a machine name (`WIN-1G2UL03927Q`) rather than a domain.

### What would raise coverage and precision

1. Label the 46,986 rule-classified org strings. They are 557,873 records at 17/25 precision. This is the cardinality-reduction job an LLM is good at: distinct strings, cached, checked against the 600 hand labels.
2. Label the domains with 5 or more IPs that the reverse-DNS rule did not catch. The tail errors are all of this kind.
3. Use `ssl_san_raw` (stored, unparsed) as a second domain source for certificate records.

---

## 4. Signal families and their prevalence

Definitions are in `views.sql` (view `s`), one boolean per record, so every table counts the same thing. Record counts are from `02_signals_by_bucket.sql`; company counts from `06_company.sql` where a company is any attributed key with at least one non-CDN record (333,230), and "estate" means a company with 5 or more IPs (21,740).

### A. Verified or active (rare, high precision)

| Signal | Records `other` | `cloud` | Companies | Estates |
|---|---|---|---|---|
| Verified + known-exploited CVE | 1,966 | 118 | 449 | 250 |
| Verified CVE, any | 4,638 | 124 | 1,017 | 415 |
| Heartbleed (`opts.heartbleed` VULNERABLE) | 158 | 2 | 49 | 21 |
| Compromise indicators (`c2`, `compromised`, `malware`, `doublepulsar`, Cobalt Strike) | 84 | 28 | 25 | 13 |

Compromise detail: `compromised` 77 records on 65 IPs (Redis instances with injected keys, product `Redis key-value store`), `c2` 31 records on 28 IPs (Sliver C2 on port 31337), `malware` 5 (PowerSploit), `doublepulsar` 1. Related but not counted: `ssh-bad-key` 80, `tor` 64, `scanner` 94.

### B. Exposed access and data (real when present, needs attribution)

| Signal | Records `other` | `cloud` | Companies | Estates |
|---|---|---|---|---|
| RDP reachable | 22,826 | 4,838 | 3,387 | 1,187 |
| RDP without NLA (no CredSSP offered) | 996 | 235 | 187 | 121 |
| VNC reachable | 4,342 | 571 | 222 | 156 |
| VNC with security type None | 10 | 0 | 2 | |
| Telnet (port 23/2323 or a login prompt) | 3,799 | 63 | 360 | 226 |
| SMB reachable | 2,626 | 90 | 467 | |
| SMBv1 enabled | 944 | 18 | 168 | 104 |
| SMB anonymous (authentication disabled) | 411 | 29 | 38 | 24 |
| FTP anonymous login accepted | 973 | 22 | 212 | 77 |
| Datastore reachable (MySQL, MSSQL, Mongo, Redis, Elastic, ...) | 14,826 | 3,090 | 2,713 | 1,052 |
| Datastore readable without auth (Mongo no-auth, Redis INFO returned, Elastic indices, rsync modules) | 270 | 48 | 68 | 40 |
| Out-of-band management (IPMI, HP iLO, VMware) | 706 | 3 | 217 | 139 |
| Kubernetes API / Docker registry / etcd / Consul / Vault | 1,271 | 3,633 | 187 | 88 |
| Metrics endpoints (node_exporter, netdata, ...) | 10,033 | 408 | 668 | 376 |
| Directory listing (`open_dir` or "Index of /") | 4,596 | 639 | 1,768 | 470 |
| Admin panels by title (phpMyAdmin, Grafana, Jenkins, Kibana, ...) | 11,188 | 945 | 4,682 | 764 |

The Kubernetes rows are weak: most are 401/403 responses from a managed control plane (GKE, AKS), which is default behaviour, not a finding.

### C. Neglect and hygiene (common, weak alone, useful as a pattern)

| Signal | Records `other` | `cloud` | Companies | Estates |
|---|---|---|---|---|
| `eol-product` tag | 167,961 | 74,185 | 40,523 (12.2%) | 5,392 (27.2%) |
| `eol-os` tag | 5,366 | 668 | 1,034 | |
| Certificate expired | 32,829 | 10,015 | 19,647 | 2,744 |
| Self-signed certificate | 97,162 | 29,381 | 19,725 | 4,495 |
| TLS 1.0 or 1.1 offered | 43,431 | 27,281 | 28,490 | 3,583 |
| SSLv2 or SSLv3 offered | 3,281 | 198 | 1,670 | |
| RC4/DES/EXPORT/NULL/MD5 cipher | 3,760 | 4,259 | 2,340 | |
| RSA key under 2048 bits | 7,589 | 257 | 1,782 | |
| SHA-1 signed certificate | 10,335 | 6,181 | | |
| Weak SSH kex or cipher (group1-sha1, 3des-cbc, arcfour, ...) | 19,314 | 3,469 | 3,632 | |
| Default web page ("IIS Windows Server", "Welcome to nginx!", "Apache2 Ubuntu Default Page", ...) | 87,061 | 24,849 | 17,003 | 4,489 (22.6%) |

### D. Device and OT surface (mostly on ISP lines, mostly unattributable)

| Signal | Records `other` | Companies | Estates | Note |
|---|---|---|---|---|
| Cameras and DVRs (Hikvision, Dahua, D-Link, ...) | 65,282 | 3,125 | 1,861 | 43,796 records are `Hikvision IP Camera` |
| Router management (MikroTik, TR-069, home gateways) | 107,311 | 7,353 | | |
| VPN endpoints (IKE, PPTP, L2TP, named appliances) | 149,932 | 10,392 | | 110,252 records are bare ISAKMP responders |
| Named edge appliance (Fortinet, SonicWall, Check Point, DrayTek, Citrix, BigIP, ...) | 36,212 | 5,456 | 1,948 | |
| NAS (Synology, QNAP, AFP, iSCSI) | 4,553 | 701 | 296 | |
| Printers | 15,330 | 720 | 422 | |
| Industrial protocols, excluding hosting IPs | 557 | 88 | | Siemens S7 110 records, BACnet 54, KNX 48, EtherNet/IP 22, Trane 11, CODESYS 5 |
| AI serving endpoints (Ollama, LiteLLM, MCP servers, llama.cpp, ComfyUI, Hermes Agent, ...) | 771 | 184 | 59 | MCP 428 records on 286 IPs; Ollama 83, of which 44 list their models; 803 more records are honeypots |

### E. Maturity (negative evidence)

| Signal | Records `other` | `cloud` | `cdn` | Companies |
|---|---|---|---|---|
| WAF detected | 78,875 | 127,920 | 1,313,972 | 26,091 |
| HSTS on a 200 response | 81,429 | 31,338 | 35,334 | 29,368 |
| CSP on a 200 response | 97,870 | 14,526 | 17,540 | 20,469 |
| `security.txt` present | 5,025 | 546 | 2,756 | 1,219 |
| Post-quantum key exchange (`pqc` tag) | 49,436 | 30,118 | 271,362 | |
| Fronted by a CDN somewhere in the estate | | | | 4,826 companies; 2,331 estates (11.8%) |

### Does neglect cluster? (`06_company.sql`, estates with 5+ IPs)

| If a company has... | ...it also has | Base rate | Lift |
|---|---|---|---|
| RDP reachable | SMB reachable: 11.1% | 1.4% | 7.7 |
| Cameras/DVRs | Telnet: 5.3% | 1.1% | 4.7 |
| EOL product | RDP without NLA: 1.7% | 0.6% | 2.8 |
| Default web page | Verified CVE: 5.5% | 2.1% | 2.7 |
| EOL product | Verified CVE: 5.4% | 2.1% | 2.6 |
| Expired certificate | Reachable datastore: 12.6% | 5.3% | 2.4 |
| EOL product | Expired certificate: 21.6% | 13.8% | 1.6 |
| WAF | Verified CVE: 2.9% | 2.1% | 1.4 |
| HSTS | EOL product: 37.1% | 27.2% | 1.4 |

Neglect signals co-occur at 2 to 8 times base rate. Maturity signals (WAF, HSTS) do **not** reduce the rate of verified CVEs or EOL software in the same estate, so they are weak as negative evidence on their own.

---

## 5. The CVE field: what it is worth (`03_vulns.sql`)

| Fact | Number |
|---|---|
| Records with `vulns` | 467,424 (3.2%); 20,988,468 CVE rows; 11,064 distinct CVEs |
| CVEs per record, `other` bucket | median 12, p90 129, max 1,000, mean 47.6 |
| Apache httpd records | mean 110.7 CVEs each; identical sets of 79, 95 and 118 CVEs are attached to every record of a given version |
| Verified (`verified: true`) rows | 4,808 records |
| KEV-flagged records, `other` + `cloud` | 274,779, dominated by three version-inferred CVEs: CVE-2023-44487 (HTTP/2 Rapid Reset, 170,651 records on 94 products), CVE-2024-38475 (76,003) and CVE-2021-40438 (49,880) on Apache httpd |
| Shodan's `kev` flag vs the CISA catalog of 2026-10-27 | 199 CVEs flagged, 199 in catalog, 2 disagreements each way. The 2 catalog-only CVEs (CVE-2026-109618/9, PHP) were added to KEV on 2026-10-26, the day of the scan, and touch 51,523 records |
| Shodan's embedded EPSS vs the FIRST feed of 2026-10-27 | correlation 0.99, mean absolute difference 0.0013, 29 CVEs differ by more than 0.1 |

**Conclusion.** A raw CVE count or a KEV count ranks web servers by distribution age, not by exploitability. Red Hat and Debian backport fixes without changing the version string, so an Apache 2.4.6 on CentOS 7 collects 118 CVEs it may not have. The field is worth using in exactly two ways: the `verified` flag, and a join to the live KEV catalog for same-day additions.

---

## 6. Is there a glaring signal?

**Yes, one: a verified, known-exploited, remotely exploitable flaw on a reachable host.** It is rare (2,084 records, 0.025% of non-CDN records), it is confirmed by the scanner rather than inferred from a version string, every instance is wormable or pre-auth RCE, and 449 of them map to a named company (193 via a high-precision route).

| CVE | What it is | Records (`other` + `cloud`) | Where it was seen |
|---|---|---|---|
| CVE-2020-0796 SMBGhost | SMBv3 compression RCE, wormable, CVSS 10 | 1,036 on port 445 | Business lines on Charter and Oman Mobile; customers of two Japanese ISPs (`au-net.ne.jp`, `so-net.ne.jp`) |
| CVE-2015-1635 / MS15-034 | IIS HTTP.sys RCE, CVSS 9.8 | about 500 on IIS 7.5, 8.0 and 8.5 | Dassault Systèmes (via certificate), Strato and Plesk default pages, Vodafone Data, IPKO |
| CVE-2019-0708 BlueKeep | RDP pre-auth RCE, wormable | 197 on port 3389 | Thai UniNet, Chulalongkorn University, link3.net |
| CVE-2014-0160 Heartbleed | OpenSSL memory disclosure | 113 | Boa web servers on cable modems, a WatchGuard Fireware XTM firewall on Comcast, Plesk panels |
| CVE-2017-7269 | IIS 6.0 WebDAV RCE | 30 | |
| CVE-2024-23897 | Jenkins CLI file read, KEV | 43 on ports 80, 443 and 8080 | |
| MS17-010 EternalBlue | SMBv1 RCE | 9 | |

The seven raw banners sampled in `07_glaring_examples.sql` (reproducible order) were all consistent with the flag: IIS version strings in the banner for MS15-034, an SMB dialect negotiation for SMBGhost. Precision on that sample is 7/7.

Thirty companies carrying it, with the CVEs, are listed by `06_company.sql`. Examples: Thai educational network (BlueKeep + MS15-034 on 5 IPs), link3.net (Heartbleed, MS15-034, BlueKeep on 3 IPs), Dassault Systèmes (MS15-034 on 2 IPs), Chulalongkorn University (IIS 6 WebDAV + BlueKeep).

### Second tier: real, severe, needs a human look before outreach

| Signal | Why it ranks below | Records (`other`) | Companies |
|---|---|---|---|
| Compromise indicators | The host is already breached or is attacker infrastructure. An IR conversation, not a prevention sale. A C2 host may be a red team | 84 | 25 |
| Datastore readable without auth | Severe, but 318 records in total and mostly on cloud VMs without a company domain | 270 | 68 |
| SMBv1 enabled or anonymous SMB | Real, half of it on Pakistani and Alaskan consumer ranges | 944 / 411 | 168 / 38 |
| RDP without NLA | Real, 1,252 records | 996 | 187 |
| IPMI / iLO on the internet | Real, firmware versions 1.77 to 3.01 seen | 706 | 217 |
| AI endpoints (Ollama with model list, LiteLLM Swagger, MCP servers) | New surface, no auth on the ones sampled, tiny counts | 771 | 184 |
| Anonymous FTP | Real but often intentional (mirrors) | 973 | 212 |

### What is not glaring, and why

- **EOL software, expired certificates, TLS 1.0, default pages.** 27%, 14%, 18% and 23% of estates have them. They describe the internet, not a prospect. They become useful only as a count across one estate, which is what the co-occurrence lifts show.
- **KEV-flagged CVEs without verification.** 35% of estates. Three version-inferred CVEs make the whole number.
- **Cameras, DVRs, routers, VPN responders.** 65k, 107k and 150k records, overwhelmingly on consumer ISP lines with no attribution route.

### Provisional ranking (v0, hand weights, `06_company.sql`)

A severity-weighted sum over the signals above, capped per signal, minus a small credit for WAF, HSTS and `security.txt`, restricted to companies attributed by a high-precision route with 2 or more IPs (44,736 companies).

| Percentile | Score |
|---|---|
| 50th | 0 |
| 90th | 4 |
| 99th | 13 |
| maximum | 139 |
| companies at 20 or above | 152 |
| companies at 40 or above | 19 |

The top of the list is universities and national research networks (Thai UniNet, Chulalongkorn, NTU Taiwan, RIT, MIT, CERNET, USP, Berkeley, Keio, Queensland), then ISPs attributed by their own domain, then a few hosters. Two caveats make this a v0:

1. The score is not normalised by estate size. A 1,279-IP university accumulates more distinct signals than a 6-IP firm with the same hygiene. The caps limit but do not remove this.
2. Some `domain`-route keys in the top 40 are still hosters (`noez.de`, `php-friends.de`, `fornex.org`) and ISPs (`so-net.ne.jp`, `au-net.ne.jp`). Those are the known 19/25 precision of that route.

---

## 7. Noise traps, consolidated

Each of these was a plausible rule that the raw banners disproved.

| Trap | Evidence | Rule now |
|---|---|---|
| Probe module name treated as the service | `teamviewer` probe: 40,350 of 44,424 records are CDN IPs. `automated-tank-gauge`: 20,650 of 27,932. The two RAT probes (`darktrack-rat` 20,685, `remcos-pro-rat` 20,056) land mostly on cloud and `other` IPs, and the detected product there is never a RAT: none (32,539), nginx (1,199), OpenSSH (662), Socks4A (532), VNC (42) | Use `product` and protocol objects, never `_shodan.module` |
| `medical` tag | 359 records; the sampled ones are nginx 400 responses on port 11112 from Meteverse CDN IPs that answer every port. No record has a DICOM, PACS or Orthanc product | Tag ignored. `dicom_product` = 0 |
| Industrial protocols on hosting IPs | Siemens S7 PLCs on RAMNODE and HostPapa VPS ranges (44 records on hosting) | Counted only on isp, enterprise, edu, gov, placeholder owners (557 of 600) |
| `telnet` object present | Appears on an SSH banner at port 63256, a VNC banner at port 6002 | Require port 23/2323 or a login prompt in the banner. 10,455 → 3,799 records |
| `redis` object present means open | Banner is `-NOAUTH Authentication required.` on most | Require `redis_version` in the returned INFO. 1,218 → 270 "no auth" records |
| `kev` flag means exploitable | 198,048 records in `other`; three version-inferred CVEs (CVE-2023-44487, CVE-2024-38475, CVE-2021-40438) account for 296,534 CVE-to-record pairs across `other` and `cloud` | Use `verified`, or join KEV only for same-day additions |
| CVE count as risk | Apache records carry identical 79/95/118-CVE blocks per version | Collapse to one fact per product/version |
| Org string is the company | 76% of `other` records are hosting, ISP or placeholder orgs; "TELUS Communications Inc" is a proxy farm | Owner class first, then attribution routes |
| Domain is the company | 6,687 reverse-DNS domains, ISP-owned domains, dynamic DNS | `infra_dom` table |
| IPs answering on 50+ ports | 2,230 IPs in `other` hold 337,603 records | Not yet filtered; candidate for the next iteration |

---

## 8. Decisions and assumptions

Confirmed with the user before starting (ask-until-final round 1):

| Decision | Choice |
|---|---|
| Engine | Flatten once to Parquet, query with DuckDB; ClickHouse benchmarked and dropped |
| Scope | Build attribution v1 in this iteration, not record-level only |
| External data | CISA KEV and FIRST EPSS joined |
| LLM use | None this iteration; hand labels committed as CSV, cardinalities measured for a later labelling step |

Defaults taken without asking:

- Honeypot-tagged records are dropped from every signal count. CDN-tagged records are excluded from exposure signals and kept only as "uses a CDN".
- Owner labels match on the first 48 characters of the org string, because the labelling sheet truncated there.
- Precision was judged by me from the fields on the record, with no external lookup. A second judge would move some calls.
- The v0 score weights are hand-set and unvalidated. No outcome labels exist.
- 1 hollow row (lone UTF-16 surrogate) was left as is.

Not done:

- No second file, so no change-over-time signals.
- No parsing of `ssl_san_raw`, SNMP `sysName`, or `http.html` for company names.
- No LLM or human labelling of the 46,986 tail org strings or the tail domains.
- The IPs answering on 50+ ports inside `other` are not yet treated as artifacts.
