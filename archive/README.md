# Archive: data exploration

Everything here was written to explore the 2026-10-26 Shodan file before or alongside the pipeline. None of it is part of the application or its pipeline. It is kept because the numbers in `docs/` were produced by these scripts and can be reproduced with them.


| Path | What it is |
|---|---|
| `scripts/ingest/flatten_duckdb.py` | Parses the raw zstd NDJSON file into `archive/data/flat/main/{banners,vulns}.parquet` |
| `scripts/eda/stride_sample.py` | Writes every Nth line of the raw stream to a sample file |
| `scripts/eda/profile.py`, `facts.py`, `noise_check.py`, `company_view.py`, `examples.py` | First-pass profiling of the 1-in-400 sample; results in `docs/eda/initial.md` |
| `scripts/analysis/08_terms.sql`, `q.py`, `views.sql` | Full-file queries over the flattened Parquet; results in `docs/terms.md` |
| `labels/*.csv` | Owner classes for org strings, domains and certificate names, read by `views.sql`. The pipeline replaced them with PeeringDB and ASdb |
| `blind-analysis/scripts/` | The blind re-analysis of the bronze tables; results in `docs/eda/blind-analysis.md`. Reads `data/runs/<sample\|full>/bronze/` |
| `explore.ipynb` | Exploration notebook over the 1-in-200 sample |
| `data/flat/main/` | Full-file Parquet from `flatten_duckdb.py`, read by the analysis scripts. Git-ignored |
| `data/samples/`, `data/work/` | Samples and intermediate outputs of the above. Git-ignored |

Run from the repository root, for example:

```sh
.venv/bin/python -I archive/scripts/analysis/q.py archive/scripts/analysis/08_terms.sql
uv run python archive/blind-analysis/scripts/00_ip_stats.py sample   # then 01 … 07; 04, 06 and 07 need 00's cache
```
