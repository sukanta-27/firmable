# Initial EDA: the dataset file

**Date:** 2026-10-27
**Input:** `data/raw/b2_download_file_by_id`, downloaded from the link in `README.md`

The file is an NDJSON dump in the Shodan banner format. **14,608,407 records**, each one an internet-facing service (`IP:port`) observed at a timestamp. Every record has a `_shodan` object holding the crawler id, the probe module and the region.

All distributions below come from a **uniform sample of 36,522 records** (every 400th line), unless stated otherwise.

---

## What was done

| # | Step | Output |
|---|---|---|
| 1 | Identified the format with `file` and `zstd -lv` | Zstandard, 1 frame |
| 2 | Extracted the first 20,000 records | `archive/data/samples/head_20k.jsonl` (143 MB) |
| 3 | Streamed the whole file once, counting records and keeping lines 1, 401, 801, … | `data/samples/stride400.jsonl` (312 MB, 36,522 records) |
| 4 | Profiled field coverage and value distributions | `archive/scripts/eda/profile.py` |
| 5 | Measured domain-based company attribution | `archive/scripts/eda/company_view.py` |
| 6 | Measured CDN noise and CVE clusters | `archive/scripts/eda/noise_check.py`, `archive/scripts/eda/facts.py` |
| 7 | Extracted one example record per category | `archive/data/samples/demo_examples.txt` |

**Not done:** full decompression to disk. The file decompresses to 114 GiB, and the disk had 153 GiB free. Every step above streams through `zstd -dc` instead.

### Reproduce

```sh
zstd -lv data/raw/b2_download_file_by_id
zstd -dc data/raw/b2_download_file_by_id | head -n 20000 > archive/data/samples/head_20k.jsonl
zstd -dc data/raw/b2_download_file_by_id | python3 -I archive/scripts/eda/stride_sample.py 400 data/samples/stride400.jsonl

python3 -I archive/scripts/eda/profile.py      data/samples/stride400.jsonl
python3 -I archive/scripts/eda/company_view.py data/samples/stride400.jsonl
python3 -I archive/scripts/eda/noise_check.py  data/samples/stride400.jsonl
python3 -I archive/scripts/eda/facts.py        data/samples/stride400.jsonl
python3 -I archive/scripts/eda/examples.py     archive/data/samples/head_20k.jsonl > archive/data/samples/demo_examples.txt
```

`data/` is git-ignored.

---

## The file

| Property | Value |
|---|---|
| Compressed size | 17,619,943,483 B (16.4 GiB). `README.md` states 9–12 GB |
| Compression | Zstandard, 1 frame, 4 MiB window, XXH64 checksum |
| Decompressed size | 122,782,583,953 B (114 GiB) |
| Records | **14,608,407** (one JSON object per line) |
| Invalid JSON lines | 0 of 56,522 parsed |
| Record size | median 924 B, p95 23,392 B, max 3,280,811 B |
| Timestamps in sampled records | 2026-10-26 00:51:04 to 2026-10-26 13:03:52. The field has no timezone |
| Ordering | Not sorted by time. Line 1 is 11:59:52, and 00:51:04 appears within the first 20,000 lines |
| IPs | 34,523 distinct in the sample. 1,639 appear on more than one port, at most 15 records for one IP |
| IPv6 | 791 records (2.2%) |

---

## Record structure

| Group | Fields | Coverage |
|---|---|---|
| Network / location | `ip`, `ip_str`, `port`, `transport`, `asn`, `org`, `isp`, `location` (city, region, country, lat/long) | 100% (`ip_str` 97.8%) |
| Names | `hostnames`, `domains` | 73.8% |
| Cloud | `cloud` (provider, region, service) | 28.4% |
| Software | `product` 18.1%, `version` 6.6%, `cpe23` 21.2%, `os` 4.2% | as listed |
| Web | `http`: status, title, headers, HTML, `waf`, `components` (detected tech), `securitytxt`, robots, sitemap | 29.9% |
| TLS | `ssl`: `cert` (subject, issuer, issued, expires, `expired`), `versions`, ciphers, chain, JARM | 6.9% |
| Findings | `vulns` (CVE id, `cvss`, `verified`, `summary`), `tags` | 3.3% / 70.8% |
| Raw | `data` (raw banner text), `_shodan.module` (probe used), `tcp` fingerprint | 100% / 100% / 96.8% |
| Protocol-specific | `ssh`, `snmp`, `isakmp`, `ntlm`, `rdp_encryption`, `mysql`, `ftp`, `dns`, … | each 1.3% or less |

---

## Distributions

| Dimension | Top values (count in sample) |
|---|---|
| Transport | tcp 35,339 · udp 1,183 |
| Port | 80 (5,496) · 443 (1,921) · 2087 (758) · 161 (464) · 8085 (381) · 500 (358) · 7547 (313) · 9000 (274) · 22 (229) |
| Probe module | `auto` 19,116 (52.3%) · `http` 5,598 · `http-simple-new` 2,863 · `https` 2,070 · `https-simple-new` 1,822 · `language-server-protocol` 685 · `snmp_v3` 460 · `ike` 358 |
| Country | US 13,828 (37.9%) · SG 11,111 (30.4%) · CN 2,032 · GB 1,107 · DE 1,061 · JP 589 · IL 544 · KR 514 · FR 450 · HK 436 · AU 164 |
| Org | Incapsula Inc 11,612 (31.8%) · Google LLC 7,819 (21.4%) · Cloudflare 1,429 · Aliyun 935 · Amazon.com 866 · Amazon Technologies 675 · Korea Telecom 407 · Akamai 382 |
| Cloud provider | Google 7,149 · Amazon 1,837 · Alibaba Cloud 632 · Azure 222 · DigitalOcean 141 · Linode 134 |
| Product | nginx 1,968 · Apache httpd 666 · CloudFront httpd 557 · AkamaiGHost 394 · OpenSSH 341 · AWS ELB 308 · OpenResty 225 · Microsoft IIS httpd 196 |
| Tags | cdn 14,616 (40.0%) · cloud 10,374 (28.4%) · pqc 905 · eol-product 642 (1.8%) · honeypot 607 (1.7%) · vpn 328 · self-signed 310 · proxy 174 · iot 80 · database 39 · ics 3 · medical 2 · c2 1 |
| HTTP status | 200 (2,814) · 404 (1,505) · 503 (1,437) · 403 (1,295) · 301 (1,182) · 400 (1,160) |
| WAF | Incapsula 1,299 · Cloudflare 868 · CloudFront 783 · Akamai Kona 394 · AWS ELB 354 · FortiWeb 72 |

---

## Findings

### 1. Most records are CDN or cloud infrastructure

- **65.9%** of records are tagged `cdn` or `cloud`.
- Incapsula and Google orgs together are **53.7%** of records.
- **94.2%** of SG records (10,463 of 11,111) have org Incapsula.

### 2. The probe module is not the detected service

- Of 1,237 `cdn`-tagged records probed with a non-web module, **1,006 (81.3%)** got a reply starting with `HTTP/`.
- Example: the `automated-tank-gauge` probe on `107.154.179.93` (Incapsula) got an HTTP 400 HTML page back.
- The `product` field names the detected service. VNC was identified on records probed by `toshiba-pos`, `handpunch`, `mqtt`, `netusb` and `clickhouse-native` modules.

### 3. Company attribution is not direct

- **73.8%** of records have a domain.
- After excluding a 33-entry list of hosting/CDN/ISP domains (`company_view.py`), **15.7%** still have one.
- That remaining set still contains ISP and hosting domains (`secureserver.net`, `wanadoo.fr`, `ono.com`, `kpn.net`, `telecomitalia.it`, `unifiedlayer.com`). So 15.7% is an upper bound for attribution by domain alone.
- Three attribution routes were seen in examples. How often each one works is **not yet measured**:

  | Route | Example |
  |---|---|
  | `org` / ASN is the company | `156.93.225.137:9122`, org "Wal-Mart Stores, Inc.", AS396982. The domain `walmart.com` appears on 27 records in the sample |
  | TLS cert subject `O=` | `store.sony.com.co`, cert `O=Sony Corporation of America` |
  | Hostname / domain | `45.124.52.99`, `mx.chud.au` |

### 4. CVEs are mostly unverified, and some are attached in blocks

- **1,190** records (3.3%) have `vulns`. **16** of them have at least one `verified: true` entry (20 entries). Of the 1,190, 16 are on `cdn`-tagged IPs.
- 3,174 distinct CVEs appear.
- A block of **12 CVEs** (CVE-2007-4723 … CVE-2013-4365) appears on exactly 325 records each.
- **311 of 666** Apache httpd records (46.7%) carry CVE-2013-4365. Its `summary` in the data describes the **mod_fcgid module before 2.3.9**. It is attached across Apache 2.4.6, 2.4.52, 2.4.58, 2.4.62 and 2.4.68.
- The 16 records with verified vulns:

  | Org | Product | CVE (CVSS) |
  |---|---|---|
  | Ziggo Consumers · NOS Comunicacoes · Telenor Sverige | D-Link DCS-932LB1 webcam 2.18 | CVE-2018-18441 (7.5) |
  | Viettel Group · Eclipse Static ADSL Pool · TT ADSL-TTnet | DrayTek Vigor 2912 / 2860 / 2620 | CVE-2022-32548 (10.0) |
  | Open Computer Network · NTT DOCOMO | SolarView Compact 4.03 / 4.02 | CVE-2023-23333 (9.8) |
  | OVH SAS | Microsoft IIS 7.5 | CVE-2015-1635 / MS15-034 (9.8) |
  | Tencent Building · Superonline | (none) | CVE-2020-0796 (10.0) |
  | JSC Kazakhtelecom (2 records) | GoAhead Embedded Web Server | CVE-2015-0204 (4.3) |
  | Eonix · Colocation America · Private Customer | (none) | CVE-2015-0204 (4.3), CVE-2015-4000 (3.7) |

### 5. TLS hygiene (2,526 records with `ssl`)

| Measure | Count |
|---|---|
| Certificate `expired: true` | 129 (5.1%) |
| Offers TLS 1.0 | 307 (12.2%) |
| Offers SSLv3 or SSLv2 | 14 |
| Tagged `self-signed` (all records) | 310 |

Example: `store.sony.com.co` is served through Incapsula on port 9943 with a certificate that expired 2016-02-26.

### 6. HTTP security headers (2,814 status-200 responses)

| Header | Present |
|---|---|
| `strict-transport-security` | 389 (13.8%) |
| `content-security-policy` | 324 (11.5%) |
| `x-frame-options` | 734 (26.1%) |
| `x-content-type-options` | 623 (22.1%) |
| `security.txt` (all records) | 21 |

### 7. End-of-life software (642 records tagged `eol-product`)

nginx 578 · Apache httpd 29 · MySQL 9 · MariaDB 5 · MongoDB 2 · Jenkins 2 · Grafana 2 · SolarView Compact 2

### 8. Remote access services

| Service | Non-CDN | CDN-tagged |
|---|---|---|
| RDP (`product` identified) | 63 | 1 |
| RDP (`rdp` probe, no product) | 42 | 6 |
| TeamViewer probe (no product) | 7 | 92 |
| VNC | 12 | 0 |
| RustDesk | 4 | 0 |

### 9. Honeypots

**607 records (1.7%)** are tagged `honeypot`. Example: `13.57.183.249:44308` on AWS serves the title `USG310` with `Server: Microsoft-WinCE/4.20`.

---

## Example records

These are from the head sample. Full versions are in `archive/data/samples/demo_examples.txt`.

| Category | Record |
|---|---|
| Company-owned IP | `156.93.225.137:9122`, org Wal-Mart Stores, Inc., `walmart.com`, empty banner |
| Exposed database | `192.185.161.11:3306`, MySQL 5.7.44-48, tags `database`, `eol-product`, org HostGator |
| Remote access | `45.124.52.99:21116`, RustDesk, `mx.chud.au`, AU |
| Expired cert | `149.126.73.79:9943`, `store.sony.com.co`, expired 2016-02-26 |
| Version-inferred CVEs | `103.179.210.39:22`, OpenSSH 7.3, 49 CVEs, all `verified: false` |
| EOL web server | `84.89.0.84:80`, nginx 1.20.1, title "Welcome to CentOS", 3 CVEs |
| VPN appliance | `212.183.165.70:4500`, Checkpoint VPN-1 / Firewall-1, IKE NAT-T |
| Probe artifact | `107.154.179.93:10001`, `automated-tank-gauge` probe, HTTP 400 reply from Incapsula |
| Honeypot | `13.57.183.249:44308`, tags `cloud`, `honeypot` |

---

## Open questions (not yet measured)

1. What share of records can be tied to a company, and by which route (`org`/ASN, cert `O=`, domain)?
2. How many distinct companies does one file cover, and how many records per company?
3. Do other monthly files share this file's mix (CDN share, countries, ordering)? Only one file has been seen.
4. What does the `auto` probe module cover? It is 52.3% of records.
