# Blind analysis of bronze: which cybersecurity signals does this data hold?

## Why this exists

An earlier analysis of this Shodan dump produced a set of findings that the rest of the project keeps relying on. I want to know whether they hold up. You will re-derive the findings **from the bronze tables alone, without seeing the earlier conclusions**, so the two can be compared afterwards. The comparison isn't your job, and neither is building anything. Your job is an independent, evidence-backed answer to one question:

**What in this data is a real cybersecurity risk to the organisation running the host, and how sure are we?**

Look past the obvious exposed services. Search the whole record for anything security-heavy: protocol objects, tags, TLS and SSH details, HTTP content, scanner test results, vulnerability fields, odd or rare keys.

## Blindness rules (strict)

**Do not open, read, grep or summarise any of these**, even to "just check":

- `docs/` (every file, including `docs/eda/` and `docs/terms.md`)
- `archive/`
- `internal/`, **except** `internal/blind-analysis/`, where you write your output
- `.claude/handoff/` and `.claude/context_ledger.md`. **Don't run `/recall`.**
- `pipeline/silver/`, `pipeline/stage.py` and `tests/`. Silver encodes the earlier conclusions
- Memory files in `~/.claude/projects/*/memory/` other than `MEMORY.md`, which loads by itself. Don't follow its pointers
- `git log -p`, `git show` and diffs of any of the above

**`CLAUDE.md` loads automatically and contains a "Domain rules that are easy to get wrong" table.** Those rules come from the earlier analysis. Treat every row as **a claim under test, not a fact**. Re-measure each one from bronze and report it as confirmed, refuted or partly true, with your own numbers. Don't use any of them as a filter until you've measured it yourself.

If you catch yourself relying on something you didn't measure in this session, stop and measure it, or label it "assumed".

## What you may use

| Source | Use |
|---|---|
| `pipeline/bronze.py` | The schema: `COLUMNS`, `PROTOCOLS`, `DROPPED`, truncation (`TRUNCATE_AT`) and the module docstring. Read it first, so you know what bronze kept, dropped and truncated |
| `data/runs/sample/bronze/{banner,vuln,cve_text}/` | Develop every query here first |
| `data/runs/full/bronze/{banner,vuln,cve_text}/` | Run the final numbers here, **read-only** |
| Bronze manifests and run logs in `data/runs/{sample,full}/_meta/` (skip anything about silver) | Row counts and the source file's identity |
| Public, dated external facts (CISA KEV, FIRST EPSS, vendor advisories, RFCs) | Only to explain what a field means. Cite the link. `data/external/` may hold KEV and EPSS files; check their dates |

**Never read `data/raw/`** (114 GiB). Read banner rows `WHERE parse_error IS NULL`. Query with DuckDB from Python or the CLI, select only the columns you need, and keep `THREADS = 8`. Don't change any code in `pipeline/`, `api/` or `tests/`.

## Method

1. **Census.** For each column, protocol object, tag value and key in `extra`: how many records have it, on how many distinct IPs. Rank them, and note anything security-relevant, including rare things.
2. **Hypothesise.** List candidate signals. For each: the bronze field it lives in, and what an attacker could do if it's true.
3. **Test each candidate against the raw reply.** For each signal:
   - **Define it as SQL** on bronze columns.
   - **Read real records.** Pull at least 10 matching records in a reproducible order (e.g. `ORDER BY md5(rec_id) LIMIT 10`) and read the actual reply text: `data`, the protocol object, `http_html`, the title. Quote what you saw. Does the reply prove the finding, or only suggest it?
   - **Check whether the field means what its name says.** Does it fire on records where the service is clearly something else (wrong port, wrong product, a generic error page)? Is it set by the scanner's test, or inferred from a version string?
   - **Check concentration.** What share comes from the top 5 IPs, ASNs, `org` values and products? Does one IP answer on many ports with similar replies? Is a scanner tag (`honeypot`, `cdn`, `cloud`, …) carried by many of the matches? Report the numbers; don't decide in advance which of these is noise.
   - **Tighten and re-measure.** If the raw replies show false matches, tighten the rule and report counts both before and after.
4. **Vulnerability fields.** Answer separately: what does a CVE on a record actually mean here? Compare `verified` with unverified CVEs, and the `kev`, `epss` and `cvss` fields against public sources. What, if anything, counts as evidence?
5. **Who gets the finding.** For each surviving signal, measure how often the record carries something that could name the organisation (hostname, certificate subject, `org`) versus only a carrier or hoster. Report it; don't build attribution.

## Output

Write everything to `internal/blind-analysis/`:

- `scripts/`: one runnable `.sql` or `.py` file per numbered step or signal. **Every number in the write-up names the script and the input (sample or full) it came from.**
- `findings.md`, containing:
  1. **Signal table:** code name · SQL definition · records · distinct IPs · top-5 concentration · proof type (scanner test / reply content / version-inferred / tag) · precision on the records you read (e.g. "9 of 10 consistent", with quotes) · attributable share · verdict (**real risk / potential risk / noise / unclear**).
  2. **Rejected candidates:** what looked like a signal and why the raw replies disproved it, with the motivating records quoted.
  3. **Claims under test:** every row of the `CLAUDE.md` trap table, marked confirmed / refuted / partly true, with your numbers.
  4. **Surprises:** anything security-heavy you didn't expect.
  5. **Not measured:** what you'd need, and why it couldn't be measured from bronze.

**Register discipline:** label every claim **measured**, **inferred** or **assumed**. Don't invent numbers. Don't weight or rank signals by severity beyond the verdict column; weights are a later decision.

## Stop

When `findings.md` is written, stop and report a short summary: how many signals were found, how many survived, the three most surprising findings, and what you couldn't measure. Don't compare against any earlier analysis, don't edit `docs/`, and don't commit.
