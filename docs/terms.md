# Term sheet

Part 1 explains each term. Part 2 says what it means for this dataset and for finding prospects.

Definitions were checked on the web on 2026-10-29; each row links its source. Every number in Part 2 comes from `archive/scripts/analysis/08_terms.sql`, run on `archive/data/flat/main/*.parquet` (the 2026-10-26 file). Signal definitions are in `archive/scripts/analysis/views.sql`.

---

## Part 1 — What each term means

### Where the data comes from

| Term | Plain meaning | Source |
|---|---|---|
| **Shodan** | A company that constantly connects to every public internet address, asks each open port "what are you?", and stores the reply. | [Shodan help](https://help.shodan.io/mastery/vulnerability-assessment) |
| **Banner** | One record: the reply one service on one IP address and port gave at scan time, plus Shodan's parsing of it. | `archive/scripts/ingest/flatten_duckdb.py` (docstring) |
| **Tag** | A label Shodan adds to a record, such as `cdn`, `cloud`, `honeypot`, `eol-product`, `self-signed` or `pqc`. | [Shodan Datapedia](https://datapedia.shodan.io/) |
| **CDN** | A network that sits in front of other companies' websites (Cloudflare, Akamai). The IP address belongs to the CDN, not to the website owner. | Datapedia (`cdn` tag) |
| **Honeypot** | A fake system set up to attract attackers. Shodan tags a service that matches a known honeypot as "most likely not a real device". | Datapedia (`honeypot` tag) |

### Who owns an IP address

| Term | Plain meaning | Source |
|---|---|---|
| **ASN** (autonomous system number) | The number of a network run by one operator, such as `AS14618` for Amazon. Internet routing uses it to know which network owns which addresses. | [NetBox docs](https://netbox.rc.umass.edu/static/docs/models/ipam/asn) |
| **`org` / `isp`** | Two organisation names Shodan attaches to the IP. On a hosted server, neither is the business using it. (Inferred from records; I found no Shodan definition of the two fields.) | Sample record `141.193.213.20`: org WPEngine, isp Cloudflare, site jamasoftware.com |
| **Reverse DNS (PTR record)** | The name an IP address points back to. The IP owner sets it, usually the ISP or hoster, not the business. | [DNSimple](https://support.dnsimple.com/articles/reverse-dns-ptr-records/) |
| **SNI** (server name indication) | The website name a client sends at the start of an encrypted connection, so a server hosting many sites returns the right certificate. | [Cloudflare](https://www.cloudflare.com/learning/ssl/what-is-sni) |
| **CPE** | A standard product name, such as `cpe:2.3:a:apache:http_server:2.4.6`. The fields are part (a = app, o = OS, h = hardware), vendor, product and version. NIST owns the dictionary. | [Wikipedia](https://en.wikipedia.org/wiki/Common_Platform_Enumeration), [NIST](https://www.nist.gov/node/589971) |

### Vulnerabilities and how they are scored

| Term | Plain meaning | Source |
|---|---|---|
| **CVE** | A public ID for one known security flaw, such as `CVE-2019-0708`. MITRE runs the program under a CISA contract, and more than 400 organisations, mostly vendors, can assign IDs. The contract nearly lapsed in April 2025; CISA said in January 2026 that it was fully funded. | [The Record](https://therecord.media/cisa-extends-cve-program-contract-with-mitre), [CSO](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html) |
| **CVSS** | A 0–10 score for how bad a flaw would be if exploited. It's based on how the flaw is reached (network or local, login needed or not, user click needed or not) and what it damages. It says nothing about whether anyone is exploiting it. FIRST, an industry body, maintains it; the current version is 4.0. Bands: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0. | [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4-0/specification-document) |
| **Who sets a CVSS score** | Usually the vendor or whoever registered the CVE. NIST's National Vulnerability Database (NVD) used to aim to add its own score to every CVE. Since 2026-04-15 it only does so for CVEs in KEV, in US federal software, or in "critical software"; the rest are labelled "Lowest Priority – not scheduled". | [NIST announcement](https://www.nist.gov/itl/nvd) |
| **EPSS** | The probability (0–1) that a flaw sees exploitation activity in the next 30 days. FIRST computes it daily with a statistical model and publishes it free. The **percentile** is the share of all scored CVEs at or below this one. | [FIRST EPSS](https://www.first.org/epss/articles/prob_percentile_bins) |
| **KEV** (known exploited vulnerabilities) | CISA's list of CVEs with reliable evidence of real-world exploitation and a known fix. Scans, research and proof-of-concept code don't qualify. US federal agencies must fix listed flaws by deadlines under directive BOD 26-04 (2026-06-10), which carries forward the criteria of the earlier BOD 22-01. | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities) |
| **Known ransomware campaign use** | A KEV field set to `Known` or `Unknown`. `Unknown` means "not confirmed", not "no". CISA changes values without announcing it. | [Dark Reading](https://www.darkreading.com/threat-intelligence/cisa-hidden-ransomware-updates-kev-catalog) |
| **`verified`** (Shodan) | `True` means Shodan tested the service and confirmed the flaw. `False` means the flaw was assumed from the software version; Shodan warns these "can have significant false positives". | [Shodan help](https://help.shodan.io/mastery/vulnerability-assessment) |
| **Backport** | A Linux distribution fixing a flaw without changing the version number it reports. A scanner that reads the version then flags a patched server. | [Greenbone forum](https://community.greenbone.net/t/vulnerabilities-not-being-detected/9963/2) |

### Named flaws that appear as verified in this data

| Name | What it is | Source |
|---|---|---|
| **Heartbleed** (CVE-2014-0160) | An OpenSSL bug that lets anyone read up to 64 KB of server memory per request, which can include passwords and private keys. It leaves no trace. | [OWASP](https://owasp.org/www-community/vulnerabilities/Heartbleed_Bug) |
| **BlueKeep** (CVE-2019-0708) | Remote takeover of older Windows through Remote Desktop, with no login and no user action. | [CISA AA19-168A](https://us-cert.cisa.gov/ncas/alerts/AA19-168A) |
| **SMBGhost** (CVE-2020-0796) | A remote takeover flaw in Windows 10 / Server 1903–1909 file sharing (SMBv3) that can spread machine to machine. | [Tenable](https://ar.tenable.com/blog/cve-2020-0796-wormable-remote-code-execution-vulnerability-in-microsoft-server-message-block) |
| **EternalBlue** (MS17-010) | The SMBv1 flaw WannaCry used to spread. | [Compass Security](https://blog.compass-security.com/2020/03/new-smbghost-vulnerability-affects-modern-windows-systems/) |
| **MS15-034** (CVE-2015-1635) | A remote code execution flaw in Windows' web server component (HTTP.sys). | CISA KEV entry (`data/external/kev.json`) |
| **FREAK** / **Logjam** (CVE-2015-0204 / CVE-2015-4000) | Tricks that force a connection down to deliberately weak 1990s "export" encryption, which an attacker can then break. | [Black Hat 2016](https://www.blackhat.com/docs/us-16/materials/us-16-Adrian-A-Retrospective-On-The-Use-of-Export-Cryptography.pdf) |
| **CVE-2022-32548** | A DrayTek Vigor router login-page bug giving full takeover without credentials. CVSS 10. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/critical-rce-vulnerability-impacts-29-models-of-draytek-routers/) |
| **CVE-2018-18441** | D-Link cameras hand out their configuration (model, MAC address, network settings) to anyone, with no login. It is an information leak, not a takeover. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-18441) |

### Encryption and certificates

| Term | Plain meaning | Source |
|---|---|---|
| **TLS / SSL** | The encryption behind `https://`. SSLv2 and SSLv3 came first, then TLS 1.0–1.3. TLS 1.0 and 1.1 were formally retired in March 2021. | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) |
| **Certificate** | A file that proves a server is who it claims to be, signed by an issuer. It names the site (`CN`) and has an expiry date. | Sample record `141.193.213.20`: CN jamasoftware.com, issuer Google Trust Services, expires 2026-12-17 |
| **Self-signed certificate** | A certificate the server signed for itself (issuer = subject), so no outside authority vouches for it. | Datapedia (`self-signed` tag) |
| **JARM** | A fingerprint of how a server sets up encryption, made by sending it 10 test handshakes. Servers built the same way get the same JARM. It's used to find attacker control servers. | [Salesforce](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a) |
| **JA3S** | A fingerprint of a server's single handshake reply. It's the passive cousin of JARM. | [Salesforce](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s/) |
| **HASSH** | The same idea for SSH (remote login): a fingerprint of the algorithms a server offers. | [Salesforce HASSH](https://github.com/salesforce/hassh) |
| **PQC** (post-quantum cryptography) | Encryption designed to hold up against future quantum computers. Shodan tags a server that accepts the ML-KEM key exchange (e.g. `X25519MLKEM768`), which protects against "record now, decrypt later". | Datapedia (`pqc` tag), [Cloudflare](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-to-origin/) |

### Website protections

| Term | Plain meaning | Source |
|---|---|---|
| **WAF** (web application firewall) | A filter in front of a website that blocks common attacks, such as injected database commands or scripts. | [OWASP](https://wiki.owasp.org/index.php/WAF) |
| **HSTS** | A response header telling browsers "only ever connect to me encrypted". | [RFC 6797](https://datatracker.ietf.org/doc/rfc6797/) |
| **CSP** (content security policy) | A response header listing which scripts and resources a page may load. It limits damage from injected scripts. | [Wikipedia](https://en.wikipedia.org/wiki/Content_Security_Policy) |
| **security.txt** | A file at `/.well-known/security.txt` saying how to report a security problem to the organisation. | [RFC 9116](https://rfc-editor.org/rfc/rfc9116.html) |

### Services that shouldn't face the internet

| Term | Plain meaning | Source |
|---|---|---|
| **RDP** | Windows remote desktop: control a PC's screen over the network. | [CISA AA19-168A](https://us-cert.cisa.gov/ncas/alerts/AA19-168A) |
| **NLA** (network level authentication) | An RDP setting that requires a login before the session starts, carried out by a protocol called CredSSP. It blocks no-login attacks such as BlueKeep. | [Microsoft RDP glossary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ab35aee7-1cf7-42dc-ac74-d0d7f4ca64f7), [CERT.be](https://ccb.belgium.be/advisories/bluekeep-windows-rdp-remote-code-execution-vulnerability-v2) |
| **SMB / SMBv1** | Windows file sharing. SMBv1 is the old version with known holes, and the standard advice is to turn it off. | [Compass Security](https://blog.compass-security.com/2020/03/new-smbghost-vulnerability-affects-modern-windows-systems/) |
| **VNC** | Cross-platform remote screen control. Some installs need no password. | [Cyble](https://cyble.com/blog/exposed-vnc-a-major-threat-to-critical-infrastructure-sectors/) |
| **Telnet** | Old remote login that sends passwords unencrypted. | [Rapid7](https://blog.rapid7.com/2020/08/21/nicer-protocol-deep-dive-internet-exposure-of-telnet-services/) |
| **Anonymous FTP** | A file server that lets anyone log in without an account. | [ExtraHop](https://www.extrahop.com/resources/detections/anonymous-ftp-login) |
| **IPMI / BMC / iLO** | A separate management chip on a server that controls it even when it's off. HP's version is iLO. An IPMI v2.0 design flaw (CVE-2013-4786) leaks password hashes, and it has no patch. | [The Hacker News](https://thehackernews.com/2026/07/24650-internet-exposed-bmcs-disclose.html) |
| **EOL** (end of life) | A product or OS version its vendor no longer patches. Shodan's `eol-product` / `eol-os` tags use endoflife.date. | Datapedia, [endoflife.date](https://github.com/endoflife-date/endoflife.date/discussions/2811) |

### Attackers and testers

| Term | Plain meaning | Source |
|---|---|---|
| **C2** (command and control) | The server an attacker uses to remotely drive machines they've broken into. | [The Hacker News](https://thehackernews.com/2023/01/threat-actors-turn-to-sliver-as-open.html) |
| **Red team** | Security staff or hired testers who attack their own organisation on purpose to find weaknesses. | Same |
| **Sliver** | An open-source C2 tool released for red teams in 2019 and also used by real attack groups. | Same |

---

## Part 2 — What it means for this data and for prospecting

Counts are banner records, not companies. "Other" means records not tagged `cdn`, `cloud` or `honeypot`: 4,807,091 records on 3,229,866 IPs. Honeypot records are excluded throughout.

### The three findings that change how to score

1. **Only `verified` vulnerabilities are evidence.** The three biggest KEV CVEs account for 301,438 record–CVE rows and none are verified. They are assumed from nginx and Apache version strings.
2. **CDN records describe the CDN, not the customer.** 86% of WAF records (1,313,972 of 1,520,767) and 77% of PQC records (271,362 of 350,916) are on CDN IPs.
3. **High CVSS and high EPSS describe the CVE, not the host.** 225,104 records carry a CVSS ≥ 9 CVE and 357,056 carry an EPSS ≥ 0.5 CVE. Either is too many to be a lead list.

### Source and ownership

| Term | In your data | What it means for prospecting |
|---|---|---|
| Banner | 14,608,407 records on 4,992,440 IPs | You sell to companies, so every signal has to be rolled up from records to a company. |
| Tags / buckets | cdn 5,862,834 · cloud 3,688,043 · honeypot 250,439 · other 4,807,091 | Exposure signals only mean something in "other", and partly in "cloud". Drop honeypots. |
| `org` / `isp` | 42,600 ASNs. `org` ≠ `isp` on 3,634,024 records. | `org` is usually the hoster or carrier, so it can't name the prospect on its own. `docs/eda/patterns.md` §2 measures this. |
| Hostnames / domains | 10,824,898 records (74%) have at least one | The main route to a company name. Reverse-DNS names set by ISPs (`1-2-3-4.isp.net`) are mixed in and must be filtered (`infra_dom` in `views.sql`). |
| SNI | 739,925 records were scanned by website name (`sni_hostname`) | The scan targeted that site, so the record belongs to it. 25 of 25 hand-checked were correct (`docs/eda/patterns.md` §3). |
| CPE | 3,054,577 records | Product and version identity. It feeds the version-assumed CVE list, so the CVEs inherit its weaknesses (inferred). |

### Vulnerability fields

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

### Encryption and certificates

| Term | In your data | What it means for prospecting |
|---|---|---|
| TLS 1.0/1.1 accepted | 134,295 records (43,431 other) | Common hygiene gap, weak alone. A version prefixed with `-` means disabled. **358,519 TLS records have an empty version list** (inferred: versions not probed), so absence isn't proof it's off. |
| SSLv2/v3 accepted | 4,039 records (3,281 other) | Rarer and older. A stronger hygiene signal than TLS 1.0. |
| Expired certificate | 53,762 records (32,829 other) | Visible neglect. Count it per company, not per record. |
| Self-signed certificate | 132,202 records (97,162 other) | Normal on device admin pages, so it's weak alone (inferred). |
| `ssl_pubkey_type` | `dsa` on 213,332 records, of which 202,923 are signed with ECDSA | The label means ECDSA (a modern key) in most cases. **Don't use it as a weak-crypto signal.** |
| JARM / JA3S / HASSH | JARM: 8,436 distinct values on 990,592 TLS records. JA3S: 846 distinct. HASSH: 96,279 records, 2,705 distinct. | Not a need signal. Useful for grouping one company's servers by build, or matching known attacker servers. |
| PQC | 350,916 records, 271,362 on CDN | Mostly reflects the CDN's settings, not the customer's maturity. |

### Website protections (signs of maturity)

| Term | In your data | What it means for prospecting |
|---|---|---|
| WAF | 1,520,767 records, 1,313,972 on CDN, 78,875 other | Mostly reflects the CDN. On its own IPs it suggests the company already buys security. |
| HSTS / CSP | HSTS 148,101 · CSP 129,936 (counted on HTTP 200 responses: 1,039,924) | Signs of a maintained website. A small negative weight at most. |
| security.txt | 8,327 records (5,025 other) | A company with a disclosure contact has a security owner, which may mean a buyer. |

### Exposed services

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
