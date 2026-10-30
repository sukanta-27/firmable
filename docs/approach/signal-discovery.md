# Signal discovery method

**Status:** steps 2, 3, 4 (in part), 6 and the hand-check of step 7 were executed on 2026-10-28 against the full file. Results and the measured numbers are in [`../eda/patterns.md`](../eda/patterns.md); that document supersedes the sample-based numbers quoted below.
**Data numbers** come from [`../eda/initial.md`](../eda/initial.md) (uniform sample, 36,522 records). Anything not measured there is labelled **hypothesis** or **unverified**.

The plan treats signal discovery as a measurement problem. Decide what a signal must prove, build the company layer the data lacks, generate hypotheses from how breaches and security purchases happen, then test each one for precision and coverage. LLMs label distinct values, never raw rows.

---

## The bar every signal must clear

| Test | Question | How the raw data already fails it |
|---|---|---|
| **Real** | Is it actually there? | 81.3% of non-web probes on CDN IPs got an HTTP reply, so probe labels there are not services (EDA finding 2) |
| **Attributable** | Can it be tied to a named company? | At most 15.7% of records carry a non-infrastructure domain (EDA finding 3) |
| **Discriminating** | Does it separate companies? | CSP is absent on 88.5% of status-200 responses (EDA finding 6), so on its own it barely ranks anyone |
| **Actionable** | Does it map to a product and a talking point? | A CVE count is not a pitch. A named, actively exploited flaw on a named device is |
| **Timely** | Why now? | One snapshot has no "change". Timing needs a second file or date fields |

---

## Step 1: Fix the decision before the data

- **Choose the product being sold.** A signal only means something relative to an offering. Exposed RDP points to MDR or zero-trust access. End-of-life software points to vulnerability management.
- **Choose the buyer.** *Hypothesis (unverified):* mid-sized organisations with budget but no dedicated security team buy most readily. Large enterprises already run security programs, and very small ones lack budget.
- **Choose the action.** For example: "a weekly list of accounts for an SDR, each with the reason to call."

**Exit:** a one-sentence ranking objective.

---

## Step 2: Build the company layer

Records are keyed by IP and sales works by account, so nothing else can be ranked until this mapping exists.

**Attribution routes**, each observed in at least one record (EDA finding 3):

1. `org` / ASN is the company itself.
2. TLS cert subject `O=` and SAN domains.
3. Hostname reduced to its registrable domain, using the [Public Suffix List](https://publicsuffix.org/).
4. The company name appears in the HTML title or body.

**Exclude** IPs that cannot belong to one company: CDN edges, shared hosting (many domains on one IP), consumer-ISP hostnames.

**Measure per route:** coverage, plus precision from a hand-check of 50 attributions.

*Hypothesis:* companies fronted by a CDN show up as the CDN, so the attributable set skews toward companies exposing their own infrastructure. Test it by comparing attributed companies with and without a CDN-fronted web presence.

**Exit:** `record → (company_key, confidence)`, plus the measured share of records that can be attributed.

---

## Step 3: Remove noise before reading signals

| Filter | Evidence |
|---|---|
| Honeypots | 1.7% of records are tagged `honeypot` (EDA finding 9) |
| CDN probe artifacts | Finding 2. Drop CDN edges only: a company's own cloud VM is a real observation |
| Version-inferred CVEs | 1,174 of 1,190 CVE records (98.7%) have no verified entry. One 12-CVE block covers 46.7% of Apache httpd records (EDA finding 4). Red Hat backports security fixes without changing the package version ([Red Hat](https://access.redhat.com/security/updates/backporting/)). A forum report says CentOS 7's httpd 2.4.6 carries fixes up to 2.4.52 ([Virtualmin forum](https://forum.virtualmin.com/t/how-to-upgrade-apache-to-latest-version-on-centos-7/114774), unofficial). Version-matched CVEs on distro packages may therefore be patched (inferred) |
| Repeated services | 1,639 IPs appear on more than one port in the sample (EDA "The file") |

Each filter gets a test built from the real record that motivated it.

---

## Step 4: Generate hypotheses from how breaches and purchases happen

All rows are **hypotheses to test**. The "supports" column is a judgment, not a measurement.

| Family | Fields / examples in this data | Supports selling | Urgency |
|---|---|---|---|
| Active compromise | `c2` tag (1 record), RAT probe modules (`remcos-pro-rat`, `darktrack-rat`), defaced page titles (not yet searched) | Incident response, MDR | Highest |
| Known-exploited exposure | `vulns` joined to the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) scores. Edge VPN/firewall appliances (Checkpoint, SonicWall, FortiWeb all appear) | Vulnerability management, MDR | High |
| Exposed access | RDP, VNC, TeamViewer, RustDesk, databases, Jenkins, Grafana (EDA findings 7–8) | Attack-surface management, zero-trust access | High |
| Neglect | `eol-product`, expired certs, TLS 1.0/SSLv3, default pages ("Welcome to CentOS"), `open-dir` | Managed security | Medium |
| Maturity (lowers need) | `waf`, `security.txt`, HSTS/CSP, `pqc` tag | Deprioritise, or upsell | Modifier |
| Installed security stack | Visible firewall/VPN vendors | Competitive displacement | Context |
| Regulated surface | `dicom`, `toshiba-pos`, `automated-tank-gauge` probe modules. Precision is unknown: tank-gauge hits on CDN IPs were artifacts | Compliance-driven buyers | Fit multiplier |
| Timing | Cert `issued` date, services new since the previous file, newly published CVEs for versions a company runs | — | Why now |

**Context for the second row:** secondary coverage of the Verizon 2025 DBIR reports that vulnerability exploitation was ~20% of breach initial access. It also reports that edge devices and VPNs rose from ~3% to ~22% of exploited targets ([Qualys](https://blog.qualys.com/qualys-insights/2025/04/22/the-verizon-2025-data-breach-investigations-report-dbir-six-trends-you-cant-ignore), [Tenable](https://www.tenable.com/blog/cybersecurity-snapshot-verizon-dbir-zeroday-vulnerability-exploits-surge-vpn-edge-device-04-25-2025)). The primary report was not read.

*Hypothesis:* a pattern of neglect across one company's estate predicts buying better than single CVE hits, because it indicates no one owns security. Score ratios across the estate, not single findings.

---

## Step 5: Mine bottom-up for unlisted signals

- **Cardinality reduction.** For `http.title`, `product`, `html_hash`, cert issuer and `http.components`, measure how many distinct values cover 90% of records. If that number is small, label those values once (by hand, plus an LLM checked against the hand labels) and cache the labels.
- **Contrast.** Find which features are over-represented on company-attributed IPs compared with hosting and consumer-ISP IPs.
- **Co-occurrence.** Find which signals cluster on the same company.
- **Read raw rows by hand.** 200 random banners from attributed companies.

---

## Step 6: Keep a signal catalog and cut aggressively

For each candidate, record:

- definition (as code)
- prevalence
- attributable coverage
- hand-checked precision (30–50 samples)
- overlap with other signals
- product it supports
- talking point

**Cut** signals that are near-universal, imprecise, or unattributable.

---

## Step 7: Validate without labels

| Method | What it shows |
|---|---|
| Hand-checked precision per signal | The signal is real |
| Case-control against public breach and ransomware-victim disclosures | Victims' estates carry the signals more often than matched controls do. With monthly history this becomes a back-test |
| A blind expert ranking of ~50 companies vs the model | Agreement (precision@k, rank correlation) |
| LLM-as-judge, used only after measuring agreement with human labels | Scaled labelling. Report the agreement rate and cost per 1k items |
| Sanity anchors | Organisations with visible maturity signals rank low on need |
| Outcome capture in the app (contacted / meeting / disqualified) | The production label set for learning weights |

---

## Step 8: Score for a salesperson

- **Priority = Fit × Need × Urgency.** Fit: can they buy. Need: evidence of a problem. Urgency: why now.
- **Start with hand weights in log-odds space.** Collapse correlated evidence: an end-of-life nginx and its version-matched CVEs are one fact. Normalise by estate size.
- **Every score carries its top three evidence lines.** That is the salesperson's opener.
- **Favour precision over coverage.** Outreach acting on a false finding damages the account relationship. Lead with help, not threats.
- **Move to learned weights** only once outcome labels exist.

---

## Step 9: Scale

- **One streaming pass:** drop noise → extract per-record features → key by company → aggregate.
- **LLM labelling runs on distinct values with a cache.** If distinct values repeat across files (unverified: only one file has been seen), cost grows with new values, not with record volume.
- **Monthly files become per-company deltas**, which supply the timing signals.
