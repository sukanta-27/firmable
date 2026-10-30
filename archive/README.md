# Archive: data exploration

Everything here was written to explore the 2026-10-26 Shodan file before the application was designed. None of it is part of the application or its pipeline. It is kept because the numbers in `docs/` were produced by these scripts and can be reproduced with them.

The hand-labelled tables these scripts read now live in `reference/labels/`, because the application pipeline uses them too.

| Path | What it is |
|---|---|
| `scripts/ingest/flatten_duckdb.py` | Parses the raw zstd NDJSON file into `archive/data/flat/main/{banners,vulns}.parquet` |
| `scripts/eda/stride_sample.py` | Writes every Nth line of the raw stream to a sample file |
| `scripts/eda/profile.py`, `facts.py`, `noise_check.py`, `company_view.py`, `examples.py` | First-pass profiling of the 1-in-400 sample; results in `docs/eda/initial.md` |
| `scripts/analysis/*.sql`, `q.py`, `views.sql` | Full-file analysis over the Parquet; results in `docs/eda/patterns.md` and `docs/terms.md` |
| `explore.ipynb` | Exploration notebook over the 1-in-200 sample |
| `data/flat/main/` | Full-file Parquet from `flatten_duckdb.py`, read by the analysis scripts. Git-ignored |
| `data/samples/`, `data/work/` | Samples and intermediate outputs of the above. Git-ignored |

Run from the repository root, for example:

```sh
.venv/bin/python -I archive/scripts/analysis/q.py archive/scripts/analysis/00_overview.sql
```
