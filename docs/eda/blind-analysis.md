# Blind bronze analysis: which cybersecurity signals does this data hold?

**Input.** One Shodan file, `file_id 71cb1991…b5b7`: 14,608,407 lines, 1 unreadable, **14,608,406 records on 4,992,440 distinct IPs** [00f]. The file covers **2026-10-25 18:13 to 2026-10-26 13:06 UTC, about 19 hours** [02f, scan window]. Every query was developed on `data/runs/sample` (stride-400, 36,522 records) first. The final numbers come from `data/runs/full`.

**Why it exists.** An independent re-derivation of the signals from the bronze tables alone, without reading the earlier analysis, so its conclusions could be tested rather than inherited. The pipeline's signal rules (`pipeline/silver/signal_rules.py`) were built from this page.

**Sources.** Every number carries a key in square brackets. It names the script in `archive/blind-analysis/scripts/` and the dataset (`f` = full, `s` = sample). The output paths below are relative to `archive/blind-analysis/` and git-ignored: rerun the script to reproduce them.

| Key | Script | Output |
|---|---|---|
| `00f` | `00_ip_stats.py full` (per-IP ports and tags, cached) | `out/00_ip_stats.full.txt` |
| `01f` | `01_census_columns.py full` (distinct IPs there are HyperLogLog estimates) | `out/01_census_columns.full.txt` |
| `02f`, `03f` | `02_census_tags_opts.py`, `03_census_protocol_keys.py` | `out/02_…`, `out/03_…` |
| `04f:<name>` | `04_signals.py full <name>` (definition = `SIGNALS[<name>]`) | `out/signals/<name>.full.txt` |
| `05f:4x` | `05_vuln_fields.py full`, section 4x | `out/05_vuln_fields.full.txt` |
| `06f:Xn` | `06_claims.py full`, section Xn | `out/06_claims.full.txt` |
| `07f:Tn` | `07_tighten.py full`, section Tn | `out/07_tighten.full.txt` |

**Registers.** A number with a key is **measured**. Any claim not backed by a key is marked *(inferred)* or *(assumed)*. Precision means "of the 12 records `04_signals.py` prints, `ORDER BY md5(rec_id)`, how many replies support the finding". It is my reading of real replies, not a labelled ground truth.

**Attributable share** (`04f`, column `pct_any_name`): the share of records that carry a hostname not shaped like an IP, or a certificate CN that is a domain. It only says a name is present, not that the name is the owner. **Concentration**: the cumulative share of the top 5 ASNs, plus the share of records on honeypot-tagged IPs (`hp`) [04f].

---

## 1. Signal table

Verdict meanings:

- **Real risk**: the reply itself shows an exploitable condition.
- **Potential risk**: the reply shows exposure or weak configuration, but exploitability depends on something not in the record.
- **Noise**: the field does not mean what its name says, or the matches are mostly fakes.
- **Unclear**: can't tell from bronze.

Counts are before → after tightening, where tightening was needed [07f].

### Real risk

| Code name | SQL (short; full in `SIGNALS` / `07_tighten.py`) | Records | IPs | Concentration | Proof type | Precision (12 read) | Attrib. | Verdict |
|---|---|---|---|---|---|---|---|---|
| `heartbleed_vulnerable` | `opts.heartbleed LIKE '% - VULNERABLE%'` | 160 | 159 | asn5 33.1% (AS45543 SaiGon Tourist Cable 21.9%); 45% Boa Web Server; hp 0% | scanner test + reply | 12/12. Hexdump returns the scanner's own payload: `..tcensus.shodan.ioSECURITY SURV…`. 160/160 contain it [07f:T3] | 30.0% | **real risk** |
| `tag_compromised` | `list_contains(tags,'compromised')` | 77 | 65 | asn5 32.5%; hp 0% | tag (reply shows it on 26 of 77) | Of all 77: 18 hold a ransom-note DB/index (matched on database/index *names*; MongoDB 4.4+ stats always contain `…CrashRecovery`), 8 show defacement text (`Hacked By Dryzxmods`, `HACKED BY TEMPIX`), 38 are readable Redis (keys not shown), 13 have nothing visible in kept fields [07f:T18] | 22.1% | **real risk** |
| `mongodb_noauth` | `mongodb.authentication = false` | 8 | 7 | too few to judge | reply content | 8/8 `listDatabases` returned. 6/8 already hold `READ_ME_TO_RECOVER_YOUR_DATA` | 12.5% | **real risk** |
| `redis_noauth` | `redis.server` or `redis.keyspace` present | 101 | 97 | asn5 37.6%; hp 6% | reply content | 12/12 `# Server\r\nredis_version:…` without auth. Keyspaces up to `keys=3810` | 18.8% | **real risk** |
| `elastic_indices` | `elastic.indices` present | 21 | 21 | AS14061 DigitalOcean 23.8%; hp 0% | reply content | 12/12 list indices with doc counts, e.g. `logs-2026.10.02` 1,174,225 docs, `magento2_product…`, `tickets` | 14.3% | **real risk** |
| `docker_registry_open` | `docker_registry.repositories` present | 29 | 29 | asn5 34.5%; hp 0% | reply content | 12/12 repository lists (`billing`, `auth-service`, `kube-apiserver`, …) | 27.6% | **real risk** |
| `ftp_anonymous` | `ftp.anonymous = true` → plus `230` line, not hp | 1,009 → 994 | 990 → 975 | asn5 55.6% (AS31898 37.7%; orgs Unified Layer 23.7%, HostGator 20.5%) | reply content | 12/12 `230 Anonymous user logged in` / `230 Anonymous access granted` | 39.0% | **real risk** (mostly shared-hosting boxes) |
| `smb_anonymous` | `smb.anonymous = true` → plus a `Disk` share | 450 → 249 | 446 → 245 | AS17557 Pakistan Telecom 50.2% | reply content | 11/12 list shares. Several are only `IPC$` (`Realtek Samba Server`), which is why the tightened rule needs a Disk share. Others show `home` with files, `public`, `share` | 6.7% | **real risk** (Disk-share subset) |
| `vnc_noauth` | `vnc.security_types."1"` → minus FictusVNC, hp | 13 → 10 | 12 → 9 | too few | reply content | 12/12 `RFB 003.008 Authentication disabled`. 2 of the 12 are FictusVNC, a VNC honeypot product (3 of 13 overall) | 15.4% | **real risk** |
| `lantronix_password` | `lantronix.password` present → MAC on one IP, not hp | 32 → 14 | 28 → 14 | AS2914 NTT 40.6% before tightening | reply content | 12/12 show a password (`"password":"n494"`, `"8563"`, `"cwel"`). But MAC `00:0B:D6:79:DA:28` with password `medu` sits on 13 IPs, a cloned template [07f:T7b] | 15.6% | **real risk** (14) |
| `printer_no_password` | HP EWS `password_status = notSet` | 61 | 59 | AS4766 Korea Telecom 29.5%; hp 0% | reply content | 12/12 `"password_status":"notSet"` with model and serial | 19.7% | **real risk** |
| `ai_llm_open` | `ollama`/`llama_cpp`/`localai`/`comfyui` present, or AnythingLLM `RequiresAuth=false` → not hp, < 20 ports | 127 → 95 | 123 → 93 | AS16509 33.1%; hp 17% | reply content (model list) | The model list is the reply to an unauthenticated API call. **12 of 82 Ollama IPs hold models pulled from raw IPs or named `cve-*`** (`103.249.201.108:9882/trigger/benign`, `cve-39721-…`), so others have already written to them [07f:T13b,T13c] | 27.6% | **real risk** |
| `ics_protocol` | S7 / BACnet / EtherNet/IP / CODESYS / KNX / PCWorx / MELSEC / Modbus reply → not hp, < 10 ports | 376 → 321 | 368 → 314 | asn5 22.3% | reply content | 8/12 real devices (`Product name: 1766-L32BWA` Rockwell, Trend `IQ4E`, Siemens `6ES7 212-1HE40`). 2 are S7 on 17–20-port hosting IPs; S7 on ≥ 10-port IPs carries templated `Plant_XXXX` ids [07f:T9b], so honeypots *(inferred)*. 2 are Modbus on honeypot-tagged AWS IPs | 13.0% | **real risk** (ICS protocols here carry no auth) |
| `tag_ssh_bad_key` | `list_contains(tags,'ssh-bad-key')` | 80 | 80 | AS8048 CANTV 48.8% | tag + reply | 12/12 Dropbear/OpenSSH host keys. The same fingerprint repeats across unrelated ISPs (`3e:75:5f:…` on 3 CANTV IPs, `86:03:d0:…` on 2), so the private key ships in firmware *(inferred)* | 3.8% | **real risk** |
| `vuln_verified` (reply shows proof) | verified CVE ∈ {CVE-2014-0160, CVE-2018-18441} | 160 + 1,061 (`opts.vulns` counts [02f] minus opts-only [05f:4l]) | — | see Heartbleed row | scanner test + reply | CVE-2018-18441: 3/3 read (T20) return the camera's MAC, LAN IP and model without auth (`"ip_address":"192.168.0.156","model":"DCS-930LB1"`). I did not check the CVE description against NVD | 30.3% (all verified) | **real risk** |

### Potential risk

| Code name | SQL (short) | Records | IPs | Concentration | Proof type | Precision (12 read) | Attrib. | Verdict |
|---|---|---|---|---|---|---|---|---|
| `vuln_verified` (version only) | verified CVE ∈ {CVE-2020-0796, CVE-2022-32548, CVE-2024-23897, CVE-2023-23333, CVE-2017-7269, MS15-034/CVE-2015-1635, MS17-010} | 4,808 total verified [05f:4a] | 4,581 | asn5 12.5%; hp 1% | scanner says verified; reply shows a version or nothing | **0/21 show the flaw** [07f:T20]. SMBGhost: `smb caps=["raw-mode"]`, SMB v2. DrayTek / Jenkins 2.346–2.429 / SolarView 4.02 / IIS 6.0: banner and version only | 30.3% | **potential** (*inferred* to be version checks for these families; method not in bronze) |
| `vuln_verified` FREAK/Logjam | verified CVE-2015-0204 / -4000 | 942 / 704 ([02f] minus opts-only [05f:4l]) | — | — | scanner test + reply | Reply DH params: 1024-bit on 684, 512-bit on ≥10, 2048-bit on 6, none on 240 (top 10 rows only) [07f:T4]. Shared hard-coded primes (`mod_ssl 2.2.x/Hardcoded 1024-bit prime` 128, `Oakley Group 2` 56) | — | **potential** (weak DH shown; export-cipher support not in kept fields) |
| `bluekeep_verified` | verified CVE-2019-0708 → minus builds ≥ 6.2 | 198 → 170 | 168 → 144 | asn5 24.7% | scanner says verified | **28 of 198 report a Windows build Microsoft lists as not affected** (10.0.20348, 10.0.19041, 6.3.9600, …). 31 are in the affected family (≤ 6.1). 139 report no build [07f:T1]. [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708) lists XP/2003/Vista/7/2008/2008 R2 | 20.2% | **potential**: "verified" is wrong on at least 14% |
| `opts_vuln_tilde` | `opts.vulns` entry starting `~` | 9 | 9 | — | scanner test | 9/9 Outlook Web App with `~CVE-2021-34473`-style (ProxyShell) entries, some alongside unprefixed ProxyLogon CVEs | 88.9% | **potential** (`~` meaning undocumented; *inferred* "possible") |
| `atg_inventory` | ATG probe reply contains `I20100` → not hp | 784 → 126 | 737 → 113 | before: hp 82%; 20.7% product `Gaspot` (an ATG honeypot) | reply content | After tightening, **4/12** look like real gauges (`TOWN OF PEMBROKE … PEMBROKE NC`, `VALERO … DEER PARK N.Y.`, TELUS `Wonowon Lower`, a Kazakh station). 8/12 are bare `I20100` echoes on 9–163-port cloud IPs, or templated stations (`HORIZON FUEL CENTER`, the same street on two hosting IPs) [07f:T10b] | 3.7% | **potential** (real ones exist; rule still mostly noise) |
| `rsync_noauth` | `rsync.authentication=false` → modules listed, not hp | 1,013 → 163 | 1,005 → 163 | Aliyun 66.7% before; hp 24% | reply content | 10/12 of the raw set list **no modules** (`{}`). Tightened lists repeat across IPs: `Public data mirror / Daily backup snapshots` on 5 IPs [07f:T6b], a lure *(inferred)* | 5.4% | **potential** |
| `ipmi_exposed` | `ipmi` present | 115 | 115 | asn5 21.7%; hp 4% | reply content | 12/12 IPMI-2.0 auth capabilities. Some advertise `null_user`/`anonymous_user`. IPMI 2.0 RAKP hands out password hashes by design ([CVE-2013-4786](https://nvd.nist.gov/vuln/detail/CVE-2013-4786)). The scanner did not retrieve one | 10.4% | **potential** |
| `esxi_exposed` | `vmware` present | 37 | 37 | asn5 27.0% | reply + version | 12/12 ESXi 5.0–6.0 / vCenter 5.5 builds (`VMware ESXi 6.0.0 build-3620759`) | 86.5% | **potential** (version-inferred) |
| `dns_open_resolver` | `dns.recursive = true` → IP seen ≤ 5 times | 6,738 → 5,419 | 5,396 → 5,381 | top-5 IP 18.0%: 8.8.8.8 is 912 records alone [07f:T14b] | reply content | 12/12 `Recursion: enabled` (one is 8.8.8.8, intentionally public) | 29.4% | **potential** (amplification) |
| `ntp_monlist` | `ntp.monlist` is an object | 10 | 10 | — | reply content | 10/10 return a client list ([CVE-2013-5211](https://nvd.nist.gov/vuln/detail/CVE-2013-5211)) | 30.0% | **potential** |
| `snmp_v1_v2` | SNMP v1 answered, or `snmp_v2` probe → with sysDescr/sysName | 14,937 → 11,597 | 14,823 → 11,516 | MikroTik 53.8% of products | reply content | 10/12 return sysDescr/sysName/contact (`RouterOS CCR2216…`, `"contact":"Dragon WiFi"`). 2 Cisco replies give version and engine only | 9.7% | **potential** (community string used not in record) |
| `rdp_exposed` | RDP reply | 28,101 | 22,634 | asn5 27.2% | reply content | 12/12 RDP handshakes with build | 20.6% | **potential** (exposure) |
| `rdp_standard_security` | protocols include `Standard RDP Security` | 2,507 | 2,136 | asn5 19.6% | reply content | 12/12 accept non-NLA security | 27.2% | **potential** |
| `smb_v1` | `smb.smb_version = 1` | 969 | 958 | AS17557 23.2% | reply content | 12/12 `SMB Version: 1`, incl. Windows Server 2012 R2 and Windows 10 Pro | 16.1% | **potential** |
| `telnet_object` | `telnet` present | 4,446 | 4,089 | AS6167 Verizon 19.9%; hp 10% | reply content | 12/12 login prompts (`Username:`, `ES450 login:` Sierra Wireless on 2332, ZTE C300 OLT on 7001) | 8.2% | **potential** (exposure) |
| `node_exporter_open` | `node_exporter` present | 10,404 | 6,885 | AS12876 Scaleway 32.8% | reply content | 12/12 hostname and kernel (`"nodename":"callrecorder-dev"`) | 11.2% | **potential** (info leak) |
| `http_dir_listing` | title `Index of /…` or `open_dir`/`open-dir` | 5,359 | 4,547 | asn5 18.1% | reply content | 12/12 directory listings (`nohup.out`, Python `SimpleHTTPServer`). Contents' sensitivity unknown | 54.9% | **potential** |
| `tag_database` | `database` tag → minus host-refused replies | 15,455 → 11,111 | 14,753 → 10,470 | asn5 21.4% | tag + reply | 6/12 handshake with version. 5/12 refuse the scanner (`Host '224.53.65.16' is not allowed`, `no pg_hba.conf entry`). 1 is an HTTP reply on 27017 | 27.9% | **potential** (port exposure) |
| `tag_medical` | `medical` tag (DICOM) | 359 | 331 | asn5 27.0%; 5% on ≥ 20-port IPs | tag + reply | 12/12 DICOM association answered `ANY-SCP`. 3 on 21–22-port hosting IPs look like honeypots *(inferred)* | 10.3% | **potential** |
| `tls_sslv2_sslv3` | `tls_versions` has `SSLv2`/`SSLv3` | 4,039 | 3,950 | asn5 24.8%; 560 cdn-tagged | reply content | 12/12 `SSLv3` accepted (`SSLv2,SSLv3,TLSv1,-TLSv1.1…`) | 73.5% | **potential** |
| `tls_weak_key` | RSA < 2048 or MD5 signature | 10,570 | 9,704 | asn5 18.1% | reply content | 12/12, mostly `rsa 1024` BT-PANEL defaults (`"O":"BT-PANEL","emailAddress":"admin@bt.cn"`) and `md5WithRSAEncryption` | 39.9% | **potential** |
| `tag_eol_os` | `eol-os` tag | 6,036 | 5,092 | asn5 27.9% | tag (version) | 10/12 show an old Windows build (6.3.9600, SQL Server 2005 on 6.1.7601). 2 (node_exporter, WinRM) show no OS version in the excerpt | 18.4% | **potential** (version-inferred) |

### Unclear and noise

| Code name | SQL (short) | Records | IPs | Concentration | Proof type | Precision (12 read) | Attrib. | Verdict |
|---|---|---|---|---|---|---|---|---|
| `influxdb_databases` | `influxdb.databases` present → minus fleet signature | 1,037 → 44 | 1,034 → 44 | asn5 62.8%; hp 0% | reply content | 12/12 list `["_internal","go_metrics"]`, bind `127.0.0.1:8088`. **993 of 1,037 share that signature** [07f:T11]; the plain set alone is 871 records across 13 ASNs [07f:T11b]. Hostnames name ISPs (`US-SPECTRUM-N`, `DTAG-COLO-N`, `OUR-RCN-N`) [07f:T11c]. Extra DBs `pwn`, `pwned_test`, `exploit_test`, `pentest_db` [07f:T11b] | 1.4% | **unclear** (untagged fleet; honeypot or managed product, *inferred*) |
| `couchdb_etcd_consul_open` | `couchdb.dbs` / `etcd` / `consul` present | 29 | 29 | hp 31% | reply content | Consul NodeID `e5ad94e9-…` repeats on 8 records [03f] (clone); etcd member lists real *(inferred)* | 6.9% | **unclear** |
| `tag_c2_malware` | `c2`/`malware`/`doublepulsar` tag or `cobalt_strike_beacon` | 38 | 35 | asn5 47.4% | tag | Products: Sliver C2 28.9%, Panda C2 21.1%, Metasploit, Mythic. These are attacker-run servers, not victims. One is `www.gov.cv` | 34.2% | **unclear** for this use |
| `screenshot_desktop_nologin` | screenshot labels have `desktop` but not `login` | 267 | 255 | AS2518 13.9% | scanner ML label | Images are dropped in bronze; OCR text is mostly NULL; labels can't be checked | 22.1% | **unclear** |
| `ssh_weak_kex` | kex has `diffie-hellman-group1-sha1` or cipher `arcfour*`/`des-cbc` | 8,694 | 8,529 | asn5 11.7% | reply content | The printed excerpt cuts off before the weak algorithm, so 0/12 confirmed by eye | 17.1% | **unclear** |
| `ldap_rootdse_anon` | `ldap` present without `errorMessage` | 1,460 | 1,138 | hp 13% | reply content | 12/12 rootDSE (`DC=VOLTRANS,DC=local`). Anonymous rootDSE is allowed by [RFC 4512 §5.1](https://www.rfc-editor.org/rfc/rfc4512#section-5.1) | 70.3% | **noise** as risk (strong naming source) |
| `ntlm_info` | `ntlm` present | 29,748 | 24,658 | asn5 25.5% | reply content | 12/12 internal NetBIOS/DNS names (`FSCLT114242.aac.dva.va.gov` in hostnames) | 21.9% | **noise** as risk (naming source) |
| `tag_eol_product` | `eol-product` tag | 244,327 | 215,739 | 89.9% nginx | tag (version) | Fires on nginx `1.28.3`, `1.28.0`, `1.26.2` and Ubuntu-packaged `1.24.0` | 32.9% | **noise** on its own |
| `cve_kev_unverified` | record has a `kev` CVE, no verified CVE | 280,577 | 247,198 | asn5 26.6% | version-inferred | 12/12 are a version string plus CPE; nothing tested. See §4 | 33.8% | **noise** as evidence |
| `cert_expired` | `cert_expired` | 53,847 | 43,568 | Incapsula 11.0%; 20% cdn-tagged | reply content | True, but CDN edges serve stale customer certs on odd ports (`store.sony.cl` on Incapsula, 76 ports) | 83.2% | **noise** as risk |
| `tag_self_signed` | `self-signed` tag | 132,202 | 98,759 | asn5 24.1% | tag | Default RDP certs (`"CN":"WIN-1G2UL03927Q"`), `TRAEFIK DEFAULT CERT`, appliance defaults | 41.9% | **noise** |
| `tag_vpn` | `vpn` tag | 127,896 | 69,902 | asn5 11.4% | tag | 12/12 IKE/OpenVPN/PPTP handshakes: a VPN gateway exists | 20.9% | **noise** as risk |
| `mcp_open` | `mcp` present → not hp, < 20 ports | 1,203 → 176 | 586 → 169 | **AS16509 93.6%**; hp 64%; 81% on ≥ 20-port IPs | reply content | 12/12 generic `"server_name":"mcp-server"` on random high ports; 24 records expose a tool list [03f] | 1.4% | **noise** (honeypot fleet) |
| `ghostcat_opts_only` | `opts.vulns` has CVE-2020-1938 → AJP 8009, no fake header, not hp | 465 → 34 | 258 → 33 | **AS16509 87.7%**; hp 63% | scanner list | 12/12 carry `X-Confluence-Request-Time` under random `Server:` headers (`JBoss-EAP/7`, `CUPS/1.1`, `Avaya CMBE`) on random ports. Never `verified` [05f:4l] | 4.3% | **noise** (34 left are unclear) |
| `jdwp` | product `Java Debug Wire Protocol` | 1,081 | 1,079 | AS37963 96.1%; **hp 100%** | reply content | 12/12 echo `JDWP-Handshake` on ports 636, 13, 9418 | 1.9% | **noise** |
| `probe_rat` | probe ∈ 12 RAT/backdoor probe names | 94,739 | 91,527 | Google 50.1% | probe name | 12/12 empty reply, no product | 2.3% | **noise** |
| `tag_honeypot` | `honeypot` tag | 250,439 | 90,476 | AS37963 61.6% | tag | Fake or empty replies (`\x00[\x00…`, echo strings) | 2.1% | **noise** source; exclusion |
| `tag_ics` | `ics` tag | 577 | 555 | asn5 17.9% | tag | Overlaps `ics_protocol`, `lantronix_password` and `atg_inventory`; judged there | 15.8% | see those rows |

**Count: 53 candidates evaluated** (`SIGNALS` in `04_signals.py`). `vuln_verified` is split into three rows by proof.

| Verdict | Candidates |
|---|---|
| Real risk | 14, plus the proof-carrying part of `vuln_verified` |
| Potential risk | 20, plus the version-only and FREAK/Logjam parts of `vuln_verified` |
| Unclear | 5 |
| Noise | 11 |
| Exclusion (`tag_honeypot`) | 1 |
| Judged through overlapping rows (`tag_ics`) | 1 |

---

## 2. Rejected candidates

| Looked like | Why the replies disproved it | Motivating records |
|---|---|---|
| RAT / backdoor present (`darktrack-rat`, `remcos-pro-rat`, `xiaongmai-backdoor`, …) | `_shodan.module` is the probe the scanner sent, not what answered. RAT probes: 94,739 records, 92.1% no product, 72.2% empty reply on `darktrack-rat` [06f:P1, 04f:probe_rat] | `34.50.147.75:10134 orcus-rat product= ` (empty) |
| Tank gauge exposed (`automated-tank-gauge` probe) | 27,932 probe records, 784 with an `I20100` inventory, 126 after dropping honeypot IPs, about 4 of 12 genuine [07f:T10, T10b] | `139.159.239.1:10001 I20100` (honeypot, 41 ports) |
| Ghostcat (CVE-2020-1938) | 4,015 records across the file carry the same `X-Confluence-Request-Time` header; 3,824 are on honeypot-tagged IPs [07f:T2b]. The CVE appears only in `opts.vulns`, never `verified` [05f:4l] | `16.51.5.77:9606 Server: JBoss-EAP/7 … X-Confluence-Request-Time` |
| JDWP open (remote code execution) | 1,081/1,081 on honeypot-tagged IPs, 96.1% Aliyun, odd ports [04f:jdwp] | `101.37.24.190:636 JDWP-Handshake` |
| MCP servers exposed | 64% honeypot-tagged, 81% on IPs with ≥ 20 ports, 93.6% AWS [04f:mcp_open] | `13.38.54.93:8578 mcp-server 2.3.0` (71 ports) |
| Open InfluxDB fleet | 993/1,037 match one signature (`go_metrics` database, bind `127.0.0.1:8088`), ISP-named hostnames, 0 honeypot-tagged [07f:T11, T11c] | `9.236.109.241:8086 "network_hostname":"US-SPECTRUM-3"` |
| Database exposed (`database` tag) | 4,344 of 15,455 replies refuse the scanner's host (`Host '…' is not allowed`, `no pg_hba.conf entry`) [07f:T16] | `122.51.24.188:3306 Error Code: 1130` |
| SMB anonymous = data exposed | 201 of 450 list no Disk share, only `IPC$` or nothing [07f:T5] | `39.36.36.93:445 [{"type":"IPC","name":"IPC$",…"Realtek Samba Server"}]` |
| rsync without auth = data exposed | 850 of 1,013 have no modules or are on honeypot IPs [07f:T6] | `8.149.105.131:873 {}` |
| CVE count / `kev` on a record = exposure | The CVE list is a function of the CPE list (§4). 47.2% of unverified `kev` entries are one HTTP/2 CVE on nginx/Apache [05f:4o] | `52.53.144.62:80 Apache httpd 2.4.52` with a CVE list and no test |
| `eol-product` = unsupported software | Fires on nginx 1.28.x and Ubuntu-maintained 1.24.0 [04f:tag_eol_product] | `84.32.83.40:80 nginx 1.28.3 tags=eol-product` |
| Self-signed / expired cert = risk | Default on RDP and appliances; CDN edges serve stale customer certs | `107.154.78.9:31337 CN=invalid.incapsula.com` (75 ports) |
| Anonymous LDAP rootDSE = misconfiguration | Allowed by RFC 4512; reveals domain names only | `51.79.170.84:636 DC=VOLTRANS,DC=local` |

---

## 3. Claims under test (`CLAUDE.md` trap table)

| Claim | Result | Numbers |
|---|---|---|
| CVE list mostly inferred from the version string; only `verified` CVEs are evidence; never rank by CVE count | **Confirmed, but `verified` is not uniformly proof** | 6,111 of 20,988,468 entries verified (0.029%) on 4,808 records [05f:4a]. 464,964/467,424 CVE records carry a CPE, and 23,361 of 23,433 distinct CPE sets map to exactly one CVE set (439,475 records) [05f:4h]. Unverified records: median 12 CVEs, p90 128, max 1,000 [05f:4g]. Verified: Heartbleed and CVE-2018-18441 replies show proof. 7 other families show only a version (0/21) [07f:T20]. BlueKeep contradicted by build on 28/198 [07f:T1]. The scanner's own list `opts.vulns` matches `verified` except BlueKeep (verified-only, 198) and Ghostcat (opts-only, 465) [05f:4l] |
| `kev` means "this version once had an exploited flaw"; use only with `verified`, or to catch same-day KEV additions | **Confirmed** | Bronze `kev` agrees with CISA KEV 2026.10.27 on every CVE ID (197 both). The 2 mismatches are Microsoft bulletin IDs `MS15-034`, `MS17-010` [05f:4c, 4n]. 2 CVEs added to KEV on 2026-10-26, the scan day, are not flagged: CVE-2026-109618 (19,210 entries), CVE-2026-109619 (32,313) [05f:4d]. 367,780 `kev` entries are unverified [05f:4b]. On unverified entries `kev` is NULL or true; `false` appears on 9 only [05f:4b] |
| CDN-tagged records describe the CDN, not the customer; exclude from exposure signals | **Confirmed** | 5,868,128 records (40.2% of all) on 556,867 IPs [06f:C1]. Incapsula 4,664,416. 5,077,148 have no Server header or product [06f:C2–C3]. Top titles `Invalid URL` 147,536 and CloudFront's `ERROR: The request could not be satisfied` 128,860 [06f:C6]. 6,210 still carry CVE lists [06f:C1]. Expired customer certs on CDN edge IPs (`store.sony.cl`, `myrewards.natwest.com` on Incapsula) [04f:cert_expired] |
| Honeypot-tagged records dropped from every signal | **Partly true: necessary, not sufficient** | 250,439 records on 90,476 IPs [02f]. Tagged honeypots make up 100% of JDWP, 64% of MCP, 63% of Ghostcat and 82% of ATG inventories [04f]. Untagged fakes remain: 191 untagged fake-Confluence records [07f:T2b]; the InfluxDB fleet (0 tagged); one Lantronix template on 13 IPs [07f:T7b]; Consul NodeID clone ×8 [03f]; templated S7 `Plant_XXXX` [07f:T9b]; templated ATG stations on hosting IPs [07f:T10b] |
| `_shodan.module` (probe) is not the service; use `product` and protocol objects | **Confirmed** | `auto` probe 7,631,835 records, 96.7% no product [06f:P1]. `telnet` probe returns OpenSSH 1,196 times; `rdp` probe returns OpenSSH 238 [06f:P2]. RAT probes 92.1% no product [04f:probe_rat]. ATG probe 0.45% genuine inventories [07f:T10] |
| `org`/`isp` usually the hoster or carrier, not the company | **Confirmed** (proxy measures) | `org = isp` on 75.1% of records. 78.1% of records have an org owning ≥ 10,000 IPs in this file; 1.4% an org with < 10 IPs [06f:O1]. The org contains the hostname domain's first label on 2.7% of record-domains [06f:O3]. Top orgs: Google 669,156 IPs, Aliyun, Korea Telecom, Amazon, Cloudflare [06f:O2] |
| Hostname domain often ISP reverse DNS; filter IP-like hostnames and the dominant domain of ISP/hosting networks | **Confirmed** | 85.7% of 10,814,580 hostnames are IP-shaped; 52.8% contain the record's own IP [06f:N1]. 60.3% of (IP, domain) pairs use their ASN's dominant domain (≥ 50 IPs and ≥ 30% of the ASN's named IPs) [06f:N2]. Top domains `googleusercontent.com` 665,216 IPs, `amazonaws.com`, `akamaitechnologies.com`, `btcentralplus.com` [06f:N3] |
| DuckDB `count_if` gives NULL on all-NULL input; `least(NULL, 3)` is 3 | **Confirmed** on DuckDB v2.0.0 | `count_if` = NULL on all-NULL and on zero rows; `count(*) FILTER` = 0; `least(NULL,3)` = 3; `greatest(NULL,3)` = 3 [06f:D1–D3] |
| Signals roll up record → company; collapse correlated evidence (EOL nginx and its CVEs are one fact) | **Correlation confirmed; roll-up untestable from bronze** | Of 243,766 `eol-product` records with a CPE, 201,835 also carry CVE lists [06f:R1]. 2.93 records per IP [06f:R2]. 8.8.8.8 appears 912 times as an open resolver [07f:T14b], so records ≠ observations |
| (Comment example in `CLAUDE.md` code rules) telnet object also appears on SSH and VNC banners; require port 23/2323 or a login prompt | **Refuted for the object; true for the probe** | 0 of 4,446 telnet objects sit on SSH/VNC content. 2,698 on 23/2323; 1,663 on other ports with a login prompt; 268 on port 23 without one [06f:T2, T1]. The *probe* named `telnet` returns OpenSSH 1,196 times [06f:P2] |

---

## 4. Vulnerability fields

| Field | What it means here | Evidence |
|---|---|---|
| CVE on a record (unverified) | A lookup from the product version, not a test | §3 row 1. Same CPE set ⇒ same CVE set for 99.7% of CPE sets [05f:4h] |
| `verified` | The scanner ran a check. For Heartbleed and the D-Link info page the reply proves it. For SMBGhost, DrayTek, Jenkins, SolarView, IIS 6, MS15-034 and MS17-010 the kept reply shows only a version or capability. BlueKeep is contradicted on 28/198 | [07f:T1, T3, T20] |
| `opts.vulns` | The scanner's own tested list, and *(inferred)* the source of `verified` except BlueKeep. Holds `~`-prefixed entries (meaning undocumented) and Ghostcat on honeypots | [02f, 05f:4l] |
| `opts.heartbleed` | Raw test log: SAFE 532,759 / ERROR 393,486 / VULNERABLE 160 | [02f] |
| `kev` | CISA KEV membership of the CVE ID at scan time; describes the CVE, not the host | [05f:4c–4d] |
| `ransomware_campaign` | Copies CISA `knownRansomwareCampaignUse`: Known 58 CVEs, Unknown 138, all matching | [05f:4e] |
| `epss` | FIRST EPSS score of the CVE (constant per CVE except 1 of 11,064; correlation 0.988 with FIRST 2026-10-27, median abs diff 0.0) | [05f:4f] |
| `cvss` | Constant per CVE (0 of 11,064 vary): CVE severity, not host exposure | [05f:4f] |

**What counts as evidence** *(inferred from the above)*: a verified CVE whose reply shows the flaw (Heartbleed, D-Link info page), or reply-content signals from §1. `kev`/`epss`/`cvss` say how bad a CVE is if present. They never say it is present.

---

## 5. Surprises

1. **The scanner's "verified" BlueKeep is wrong on at least 14%.** 28 of 198 records report Windows builds Microsoft lists as unaffected (Server 2022 `10.0.20348`, Windows 10 `10.0.19041`, 2012 R2 `6.3.9600`) [07f:T1].
2. **Several untagged honeypot fleets.**
   - InfluxDB: 993 records [07f:T11].
   - The fake `X-Confluence-Request-Time` header: 191 untagged records [07f:T2b].
   - A Lantronix clone: one MAC on 13 IPs [07f:T7b].
   - A cloned Consul node ID ×8 [03f].
   - Templated S7 plants [07f:T9b].
   - Templated ATG fuel stations on hosting IPs [07f:T10b].

   Dropping the `honeypot` tag is not enough.
3. **Attackers have already written to the open services.**
   - 6 of 8 open-MongoDB records (5 of 7 IPs) hold a database named `READ_ME_TO_RECOVER_YOUR_DATA`. 12 Elasticsearch servers hold a 1–2-document `read_me` index beside their real ones. 4 web servers had their whole page replaced by one note: `to recover your files, kindly send 0.1 BTC to bc1q9nh4…h0sp2 and tweet …, then we will help u <3`. None of the 4 web pages carries the `compromised` tag [07f:T21, T21b]. Bronze keeps database and index names only, so the database notes' text is not in the data.
   - 12 of 82 open Ollama IPs hold models pulled from raw IPs or named `cve-*` [07f:T13c].
   - Open InfluxDBs hold databases named `pwn`, `pwned_test`, `exploit_test`, `pentest_db` [07f:T11b].
4. **Heartbleed is still live on 159 IPs in October 2026.** 72 records are Boa embedded web servers; 35 sit on one Vietnamese cable ISP [04f:heartbleed_vulnerable].
5. **Lantronix device servers send their password in a UDP reply** (port 30718). 14 unique devices after removing clones [07f:T7].
6. **The scanner's own address is masked to 224.0.0.0/4.** 3,567 MySQL refusals echo a 224.x client address [07f:T19], as do NTP monlist entries [04f:ntp_monlist]. Masking is *inferred*: 224/4 is multicast and cannot be a real TCP client.
7. **41% of records (6,026,270) come from 81,287 IPs answering on ≥ 20 ports** [00f]. 58,650 of the untagged ones are Incapsula edges [06f:H4], which is why ports such as 2087, 49767 and 9067 rank in the top 60 [02f].
8. **The file spans about 19 hours, not a month** [02f]. Anything "new this month" can't be measured from it.
9. **Records repeat per service.** 8.8.8.8 port 53 appears 912 times [07f:T14b]; 2.93 records per IP overall [06f:R2].

---

## 6. Not measured

| What | Why not from bronze |
|---|---|
| How the scanner's `verified` checks work for SMBGhost, DrayTek, Jenkins, SolarView, IIS, MS17-010 | Not recorded; the kept reply shows version only. Needs the scanner's module source or vendor documentation |
| Whether readable shares, FTP directories, rsync modules or directory listings hold sensitive data | Only names are recorded. `data`/`http_html` are truncated at 4,000 characters (`TRUNCATE_AT`, `pipeline/bronze.py:29`) |
| SNMP community string the scanner used; whether SNMP is writable | Not in the record |
| Screenshot content | `screenshot.data` dropped (`DROPPED`, `pipeline/bronze.py:163`); only ML labels and OCR survive in `extra` |
| Default or weak credentials | The scanner tries only anonymous FTP/VNC-style access |
| Ground truth for honeypots | No labelled set. Untagged-fleet calls rest on cloning evidence (identical MACs, node IDs, templates), *inferred* |
| Owner of the host (company vs hoster) | Attribution not built by design. Measured only that a name is present (attrib. column) |
| Change over time (new vs persistent exposure) | One ~19-hour file |
| Meaning of the `~` prefix in `opts.vulns` | Undocumented in the data |
| Signal precision beyond 12 records each | Each verdict rests on 12 reads plus the aggregate measurements cited. No sampled error rate |

---

## Blindness disclosures

- To find the bronze run logs I summarised every file in `data/runs/*/_meta/run/`. That printed silver run-log row counts and silver table names (`sightings`, `service`, `identity_evidence`, …). I used none of it.
- No `docs/`, `archive/`, `pipeline/silver/`, `pipeline/stage.py`, `tests/` or git history was read.
