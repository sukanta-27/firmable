# Signals, scores and ranking

How a scanner reply becomes a company at the top of the list: **find** the problem in the reply, **score** how bad that kind of problem is, **attribute** the service to a company, and **rank** the companies. Every number is from the 2026-10-26 file, run through the pipeline on the full file.

## 1. What counts as a signal

**A signal is something the reply itself shows,** never the scanner's guess about it. The rules are in `pipeline/silver/signal_rules.py`, one SQL expression per finding type. They were built from the blind analysis (`docs/eda/blind-analysis.md`), which read real replies for each candidate and rejected the ones that didn't hold.

**What was ruled out, and why** (evidence in `docs/eda/blind-analysis.md` §2–§3):

| Looks like a signal | Why it isn't |
|---|---|
| A CVE listed on a record | Looked up from the version string, not tested. Only `verified` CVEs are kept |
| The `kev` flag on a CVE | Says the CVE was exploited somewhere, not that this host has it |
| The scanner's probe name (`darktrack-rat`, `automated-tank-gauge`) | It's what the scanner sent, not what answered |
| The `eol-product` tag | Fires on current nginx releases |
| Self-signed or expired certificates, VPN gateways, anonymous LDAP | Normal on appliances, remote desktops and directory servers |

**Services that never reach a signal rule** (`pipeline/silver/service.py`, full file):

| Excluded | Services | Why |
|---|---|---|
| Honeypot-tagged addresses | 260,732 | Their findings are bait |
| Addresses answering on more than 50 ports | 5,285,023 | A real server doesn't; honeypot fleets and CDN edges do |
| CDN edges with no website name | 663,757 | The reply describes the CDN, not its customer |

That leaves **7,460,589 services**. Tagged honeypots aren't the only fakes, so some rules carry their own filter. A Lantronix password counts only when its MAC sits on one address: one MAC with password `medu` sits on 13. Industrial-controller replies count only on addresses with fewer than 10 ports, because S7 on busier addresses carries templated `Plant_XXXX` ids.

## 2. The finding types

**Score** is out of 12, explained in §3. **Found** counts services anywhere in the file. **Named** counts services tied to a company (§4), the only ones a salesperson sees.

| Finding | What the reply shows | Found | Named | Companies | Score |
|---|---|---|---|---|---|
| `ransom_note` | A database or index named like a ransom note, or a web page asking for bitcoin to recover files | 22 | 5 | 5 | 12 |
| `tag_compromised` | Scanner tag for a compromised service: ransom-note databases, defaced pages | 70 | 4 | 4 | 12 |
| `redis_noauth` | Redis answering commands with no password | 86 | 4 | 4 | 12 |
| `elastic_indices` | Elasticsearch listing its indices and document counts | 21 | 1 | 1 | 12 |
| `rdp_exposed` | Windows Remote Desktop open to the internet | 22,183 | 2,369 | 1,813 | 9 |
| `tag_database` | A database answering, after dropping replies that refuse the scanner | 10,791 | 1,085 | 983 | 9 |
| `telnet_object` | A telnet service answering | 3,795 | 95 | 89 | 9 |
| `esxi_exposed` | VMware ESXi or vCenter management with its build | 37 | 10 | 9 | 9 |
| `lantronix_password` | A device server sending its password in the reply | 14 | 3 | 2 | 9 |
| `ftp_anonymous` | FTP accepting anonymous login (`230` reply) | 971 | 206 | 156 | 8 |
| `heartbleed_vulnerable` | The Heartbleed test returning the scanner's own payload | 159 | 22 | 22 | 8 |
| `ai_llm_open` | An AI model server listing its models with no login | 93 | 15 | 15 | 8 |
| `ics_protocol` | An industrial controller answering S7, BACnet, Modbus or similar | 314 | 10 | 10 | 8 |
| `atg_inventory` | A fuel tank gauge returning its inventory | 109 | 7 | 7 | 8 |
| `smb_v1` | Windows file sharing on SMB version 1 | 951 | 79 | 78 | 6 |
| `tag_medical` | A DICOM medical imaging server accepting any caller | 329 | 27 | 26 | 6 |
| `ipmi_exposed` | Server management (IPMI) open to the internet | 109 | 5 | 5 | 6 |
| `docker_registry_open` | A container registry listing its repositories | 29 | 5 | 5 | 6 |
| `printer_no_password` | An HP printer reporting no admin password set | 59 | 2 | 2 | 6 |
| `tls_sslv2_sslv3` | A server accepting SSLv2 or SSLv3 | 3,436 | 1,434 | 1,320 | 4 |
| `snmp_v1_v2` | SNMP v1/v2 returning the device's description | 11,501 | 685 | 580 | 4 |
| `dns_open_resolver` | A DNS server answering anyone's recursive queries | 5,345 | 342 | 324 | 4 |
| `rdp_standard_security` | Remote Desktop accepting its older, weaker login security | 2,115 | 279 | 232 | 4 |
| `tag_ssh_bad_key` | An SSH host key known to ship in firmware | 80 | 2 | 2 | 4 |
| `ntp_monlist` | An NTP server returning its client list | 10 | 2 | 2 | 4 |
| `http_dir_listing` | A web server listing a directory's files | 5,008 | 2,024 | 1,426 | 3 |
| `node_exporter_open` | A Prometheus node exporter revealing hostname and kernel | 6,858 | 620 | 374 | 3 |
| `rsync_noauth` | rsync listing modules with no login | 156 | 24 | 24 | 3 |
| `smb_anonymous` | Windows file sharing listing a disk share to anyone | 238 | 13 | 12 | 3 |
| `tls_weak_key` | A certificate with an RSA key under 2048 bits or an MD5 signature | 9,703 | 1,133 | 1,011 | 2 |
| `tag_eol_os` | Scanner tag for an operating system past end of life | 5,102 | 709 | 567 | 1 |
| `opts_vuln_tilde` | Scanner test entries marked `~` | 9 | 8 | 8 | unscored |
| `mongodb_noauth` | MongoDB listing its databases with no login | 8 | 0 | 0 | 12 |
| `vnc_noauth` | VNC remote screen with authentication disabled | 10 | 0 | 0 | 12 |

**Verified CVEs** are findings too: 24 CVE types on 622 named services at 570 companies.

## 3. How bad each finding type is

**No one on the team can judge security severity, so a model answers three factual questions per finding type** (68 types: the 34 above plus 34 verified CVEs). The questions are adapted from CISA's SSVC (`pipeline/ref/finding_score_prompt_v1.md`):

| Question | Answers |
|---|---|
| Is this kind of hole being exploited? | none · proof of concept · active |
| Can an attack be automated? | yes · no |
| What does an attacker get? | information · partial control · total control |

**A fixed table turns the answers into a score** (`ssvc_v1` in `pipeline/gold/finding.py`):
- **Severity:** information 1, partial 2, total 3.
- **Likelihood:** active and automatable 4, active 3, proof of concept and automatable 3, proof of concept 2, none 1.
- **Score:** severity × likelihood, from 1 to 12.
- **A CVE on CISA's KEV list counts as actively exploited,** whatever the model said. The model's own answer is kept beside it as `exploitation_blind`.

**Assumption, not validated:** the table and its numbers were drafted by AI and accepted as they are. How the answers were checked is in `docs/evaluation.md`.

**A finding type with no valid answer stays unscored** and is never guessed. Two of the 68 types are unscored; on this file they carry 22 findings.

## 4. Whose service is it?

Most addresses belong to a hoster, an ISP or a cloud, not to the business using them. Silver classes every address's owner from the scanner's tags and the network's PeeringDB type. Gold drops ASdb "landlords" and then picks a company with `rules_ab_v1` (`pipeline/gold/attribution.py`):

1. **Rule A: drop landlord names.** A domain on 10 or more addresses on networks it doesn't own, with about one service per address, is a hoster naming its rented machines (`vps-6457677-x.dattaweb.com`). It stops counting, except as a scan hostname, because someone deliberately pointed that name at the address.
2. **Rule B: the strongest remaining clue names the company.**

| Clue | Confidence |
|---|---|
| The website name the scanner asked for | High |
| The domain a Windows or directory server reports for itself | High |
| Reverse DNS | Medium |
| No name, but the address is on the company's own network | Medium |
| Two or more domains disagree | Low |

**This is the biggest limit of the whole tool.** Of 81,554 services with a finding, **10,005 (12.3%) can be tied to a company.** 83,272 of 95,564 findings sit on services nobody can name.

Where the 71,549 unnamed services with a finding sit, by the network's owner class: ISP 43.6%, no class found 23.5%, hosting 17.8%, cloud 13.7%, a company's own network 1.4%.

**Known leak:** rule A's "about one service per address" cut-off is an assumption, and shared hosting gets through it. `bluehost.com`, `godns.net`, `mtn.co.ug` and `hz-hosting.se` are landlords by name and still appear as companies, ranked 755 to 2,271 under the default rule.

## 5. Who goes first

**Default rule `worst_x_confidence_v1`:** a company's worst finding score × the confidence weight of the service that carries it (`pipeline/gold/company.py`).
- **Weights:** High 1.0, Medium 0.7, Low 0.4. **Drafted by AI, not validated.**
- **Why the worst finding:** an attacker needs one hole. The rule can't double-count one fault reported two ways, and it doesn't push a company up for being big.
- **Comparison rule `sum_x_confidence_v1`** sums instead. Both run on every build. They share 12 of their top 100 companies (`docs/evaluation.md`).

**Ties decide much of the order.** Under the default rule, 636 companies share a score of 9.0 and 2,162 share 6.3. Ties break on confidence, then the number of distinct finding types, then the share of the company's visible services with a finding, then the key. 5,098 of the 8,106 companies have one visible service, so "share" is 100% for all of them. Among those with the same score, confidence and number of finding types, the order is alphabetical.
