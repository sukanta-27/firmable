## Context

Imagine you're building for the sales team at a **cybersecurity software company**. Out of thousands of businesses in their market, which ones need cybersecurity help right now, and how do they reach them first? Your job is to turn raw company data into a tool that answers that.

## The Task

Build a small **sales intelligence platform** that helps a sales team find, rank and target the businesses most likely to buy cybersecurity software. Start from how B2B sales teams actually prospect, and let real use cases decide what you build.

## Dataset

Use the dataset below as the **core** of your prototype.

Dataset (9–12 GB compressed, downloads as soon as you click) link: https://f001.backblazeb2.com/b2api/v1/b2_download_file_by_id?fileId=4_z53658c377a6f469082f90a15_f217ef91492e93402_d20261026_m132500_c001_v0001137_t0000_u01793021100615

- This is one file. In production, hundreds to thousands of files like it arrive every month, so design ingestion and scoring to keep up with that volume
- Look for the hidden signals. What in this data tells a salesperson *"this company needs cybersecurity help"*? The best ones won't jump out if you hand the file straight to Claude or ChatGPT. Understand what's in it yourself before you point a coding agent at it
- Drafting outreach emails with LLM API calls or designing a great UI isn't the interesting part. Spend your time on the signals and what they say about each company

## How We Work

Firmable is fully **AI-native**. AI is the workflow, not a tool bolted on. We'll look at **how you build** as much as what you ship, and we're eager to see out-of-the-box ideas, in the signals, in the scoring, and in your dev loop. If you use LLMs, show us how you know they're right and what they cost.

## Deliverables

1. **A working, hosted app** where a salesperson can find and prioritise accounts. Share the link.
2. **A Git repository** with your source code and a short write-up of your approach, your key decisions, and how you measured whether it works.
3. Please share your submission within **5 days** of receiving this task.

Looking forward to seeing what you build. 🚀
## Analysis so far

| Document | What it holds |
|---|---|
| `docs/eda/initial.md` | Profile of a 1-in-400 sample: format, fields, first noise traps |
| `docs/approach/signal-discovery.md` | The method: what a signal must prove, attribution routes, validation |
| `docs/terms.md` | Term sheet: each security term in plain English, then what it means on this data (`archive/scripts/analysis/08_terms.sql`) |
| `docs/eda/patterns.md` | Full-file results: owner classes, company attribution v1 with measured precision, signal families with record and company counts, the CVE field's worth, the one glaring signal, noise traps |

### Run it

```sh
uv venv .venv && uv pip install -p .venv/bin/python duckdb
.venv/bin/python -I archive/scripts/ingest/flatten_duckdb.py data/raw/b2_download_file_by_id archive/data/flat/main --compression zstd --ignore-errors
.venv/bin/python -I archive/scripts/analysis/q.py archive/scripts/analysis/00_overview.sql
```

`archive/scripts/analysis/q.py` runs any SQL file or string against the Parquet. It loads `archive/scripts/analysis/views.sql` first, which defines the owner bucket, the signal booleans and the hand-label tables in `reference/labels/`. Files are numbered in the order they must run; `05_attribution.sql` writes `archive/data/work/attr.parquet` that `06` and `07` read.
