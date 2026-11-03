# Pipeline: how one scan file becomes a ranked list

One Shodan file goes through five steps. Each step reads and writes Parquet tables partitioned by `file_id` (the file's SHA-256), and each is one `pipeline` command.

| Step | What it holds | Full file, 2026-10-26 scan |
|---|---|---|
| **Landing** (`pipeline/landing.py`) | The file's hash, compression and line count, read in one pass and never unpacked to disk | 17.6 GB zstd, 14,608,407 lines, **131 s** |
| **Bronze** (`pipeline/bronze.py`) | Every record typed, nothing dropped or invented. A line that isn't JSON becomes a row with `parse_error` set | 14,608,407 rows (1 unreadable), 20,988,468 record × CVE rows, **262 s**, 13.2 GB peak process memory |
| **Silver** (`pipeline/silver/`) | Records folded into services, who owns each address, every clue to a company name, every finding | 13,670,101 services, 4,992,440 addresses, 101,162 finding rows, **43 s** |
| **Gold** (`pipeline/gold/`) | Which company each service belongs to, how bad each finding is, and one rank per company per scoring rule | 8,106 companies with a finding, 8,092 ranked, **4 s** |
| **Publish** (`pipeline/publish.py`) | One scan's app tables and its provenance copied to `data/publish/`, the only folder the app reads | 1.0 MB |

Times are wall clock on one Apple M4 Pro laptop (12 cores, 24 GB), from the run logs in `data/runs/full/_meta/run/`.

## Why this shape

| Decision | Why | Rejected |
|---|---|---|
| **Separate layers, each stored** | Rules change far more often than the data. Reading the raw file costs 393 s (landing plus bronze), while silver and gold together cost 47 s. A new signal rule or scoring weight reruns only the layers after bronze | One script from raw file to ranking: every rule change would re-read 114 GiB |
| **DuckDB over Parquet, one machine** | The heaviest step peaks at 13.2 GB, which fits a laptop. Every layer is a set of SQL queries over columnar files | Spark: a cluster for a job one machine finishes in minutes. Postgres: a server to run for data that is written once per file and then only read |
| **A plain CLI, no orchestrator** | Four commands per file, each resumable with `--from <step>` | Airflow, dbt, Kafka: scheduling and streaming machinery with nothing to schedule yet |
| **The pipeline runs locally; only the app is hosted** | The raw file is 17.6 GB. The app needs 1.0 MB of it: findings on services that name a company (`pipeline/gold/company_finding.py`) | Running the pipeline on the host |

## What makes a rerun safe

- **Nothing is lost or invented.** Landing counts lines independently of the parser. Bronze's blocking check compares the two: 14,608,407 rows against 14,608,407 lines on the full file.
- **A layer publishes only when every blocking check passes.** Steps write to a staging folder, which is renamed into place at the end (`pipeline/stage.py`). A failed run leaves the published tables untouched and keeps finished steps, so `--from <step>` resumes it.
- **Rerunning a file replaces only its own `file_id` partition.** A second run never appends a duplicate.

## Keeping up with hundreds to thousands of files a month

**Measured:** one 17.6 GB file takes about **7.3 minutes** end to end on one laptop.

**Inferred, not measured:**
- 1,000 files of the same size would take about 122 hours in sequence on one machine.
- Files never read each other's partitions, so they can run on separate machines at the same time. That has not been built or tried.

**Not built:** state across files. The file spans about 19 hours of scanning (`docs/eda/blind-analysis.md` §5), so "new since the last scan" needs a second file and a cross-file table.
