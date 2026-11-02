# CLAUDE.md

Sales intelligence for a cybersecurity vendor: turn monthly Shodan banner dumps into a ranked list of companies that need security help now, each with the evidence a salesperson can open with. The brief is `README.md`. What the data actually contains, measured, is in `docs/`.

**Read before touching signals or scoring:** `docs/eda/patterns.md` §7 (noise traps) and `docs/terms.md` Part 2. Most plausible rules on this data are wrong, and those two pages say which.

## Stack and commands

Python 3.12, FastAPI, Pydantic v2, pydantic-settings, DuckDB over Parquet. Managed with `uv`; never `pip install` into `.venv`.

| Task | Command |
|---|---|
| Install / sync | `uv sync` |
| Add a dependency | `uv add <pkg>` (dev: `uv add --dev <pkg>`) |
| Bronze for one file | `DATA_ROOT=data/runs/sample uv run python -m pipeline bronze data/samples/stride400.jsonl` (add `--from cve_pass` to resume a failed run, `--force` to rebuild) |
| PeeringDB snapshot (silver needs one) | `uv run python -m pipeline ref peeringdb` (writes `data/ref/peeringdb/as_of=<UTC date>/`) |
| Silver for one file | `DATA_ROOT=data/runs/sample uv run python -m pipeline silver data/samples/stride400.jsonl` (same `--from <step>` and `--force`) |
| Gold for one file | `DATA_ROOT=data/runs/sample uv run python -m pipeline gold data/samples/stride400.jsonl` (same `--from <step>` and `--force`; needs an ASdb snapshot in `data/ref/asdb/as_of=<YYYY-MM>/`, downloaded by hand from asdb.stanford.edu) |
| Finding-score prompt | `DATA_ROOT=data/runs/full uv run python -m pipeline ref finding-scores render`, then `… import --answers <reply.json> --model <id>` and `… check` |
| Finding-score answers through the API | `uv run python -m pipeline ref finding-scores ask --render <render folder>` (model from `FINDING_SCORES_MODEL`; `count` instead of `ask` counts input tokens only). Needs `ANTHROPIC_API_KEY` in the environment |
| LLM cost and token totals | `uv run python -m pipeline ref llm-usage` (also writes `llm_usage/summary.json`) |
| Attribution on the synthetic cases | `uv run python -m pipeline eval attribution` |
| Compare the company scorers | `DATA_ROOT=data/runs/full uv run python -m pipeline eval ranking <source>` |
| Publish one scan for the app | `DATA_ROOT=data/runs/full uv run python -m pipeline publish <source>` (writes `data/publish/`, all the app reads) |
| Run the API | `uv run uvicorn api.main:create_app --factory --reload` (reads `APP_USERS`, `SESSION_SECRET` and `COOKIE_SECURE=false` from `.env`) |
| Add an app user | `uv run python -m api hash-password` |
| Tests | `uv run pytest` |
| Lint + format | `uv run ruff check --fix . && uv run ruff format .` |
| Types | `uv run mypy` (folders listed in `pyproject.toml`) |

A hook (`.claude/hooks/ruff.sh`) formats and lints every `.py` file you write. If it reports an error, fix it before moving on.

Before saying work is done: `ruff check`, `mypy` and `pytest` pass, and you ran the thing you changed (the pipeline step on the sample, or the endpoint with a real request).

## Layout

| Path | What it is | Rule |
|---|---|---|
| `pipeline/` | Landing → bronze → silver → gold, and the `pipeline` CLI. Runs on our machine, never on the host | Each stage reads and writes Parquet tables, not Python objects |
| `api/` | FastAPI app. Reads gold Parquet through DuckDB, read-only | Thin: query, validate, return. Never imports `pipeline/`, which the deployed image doesn't hold. `api/reports.py` is the eval reports' schema: the pipeline imports it to write them, so it stays plain Pydantic |
| `web/` | React + Vite frontend, built into static files that `api/` serves | |
| `tests/` | Tests | See "Tests" below |
| `docs/` | Findings, each number traceable to a script | Amend in place when wrong; never add a contradicting doc beside it |
| `archive/` | Frozen exploration scripts that reproduce the numbers in `docs/` | **Read-only.** Never import from it. Copy what you need into `pipeline/` |
| `data/` | Raw dump, samples, external feeds (KEV, EPSS). Git-ignored | See "Data" below |
| `finding_scores/` | The AI's validated answers per finding type, which gold scores with. Committed | Written only by `pipeline ref finding-scores import` or `ask`. Never edited by hand |
| `llm_usage/` | One row per LLM API call (`calls.jsonl`) and the totals over it. Committed | Append-only; written only by `pipeline/llm_usage.py` |

`web/` doesn't exist yet. Create modules when the first code needs them, not ahead of it.

## Data

- **`data/raw/` holds one 17.6 GB zstd-compressed file (114 GiB of NDJSON). Never read, `cat` or `head` it.** Read the bronze tables in `data/runs/<dataset>/bronze/` instead. Their schema is `COLUMNS` and the module docstring in `pipeline/bronze.py`; read banner `WHERE parse_error IS NULL`.
- Develop against `data/samples/stride400.jsonl` (every 400th record, 36,522 lines). Run the full file only to verify.
- **Never use a full-file run as the test.** Reproduce a failure on a real slice of the raw file first (`zstd -dc <file> | head -n 2000000 | zstd -1 -o slice.jsonl.zst`), measure the fix there with the pipeline's memory logging, then run the full file once.
- Every layer is partitioned by `file_id` (the source file's SHA-256). Rerunning a file replaces only its own partition, never appends a duplicate.
- **One data root per dataset** (`DATA_ROOT`, e.g. `data/runs/sample/`, `data/runs/full/`). The sample is a subset of the full file, so the two must never share a root.
- Labels, weights and rules are tables or config, so re-scoring is a query, not a re-parse.
- **Never build a Pydantic object per banner record.** 14.6M records go through DuckDB/Arrow. Pydantic validates the edges: API input/output, settings, LLM responses, and per-company results.

## Code rules

### 1. No abstraction until something is used in two places

- One implementation means no base class, `Protocol`, factory, repository, service layer or wrapper. Call DuckDB and FastAPI directly.
- Write it inline first. Extract a function when a second call site appears, not in anticipation of one.
- Duplicating something once is cheaper than the wrong abstraction. If the two copies are drifting apart, leave them apart.
- No config knobs, flags or parameters nobody sets yet.
- **The one exception is rule 3.** A strategy registry with a single entry is allowed, because being able to switch is a requirement.

### 2. Comments say what the code cannot

The code says *what*. A comment earns its place only by saying *why*:

- A data fact behind a rule: `# hostnames[] repeats the scan hostname on almost every record; drop the echo or one clue counts as two routes agreeing`
- An alternative rejected, and the reason
- A trap the signature can't show: `# count_if returns NULL, not 0, when every input is NULL`
- A workaround, its cause, and what retires it

Never: narrating the next line, restating a name, section banners, docstrings that re-list parameters, changelog prose ("now uses", "added"), or `TODO` without an owner. If a block needs a comment to be understood, rename or extract first. Most functions need none.

### 3. Every decision point can switch strategy

Attribution, scoring, ranking and any LLM call are guesses we expect to replace. Each one is a plain function behind a named registry, chosen by config, so swapping it is a one-line change and never a rewrite.

```python
# pipeline/score.py
Scorer = Callable[[duckdb.DuckDBPyConnection, str], duckdb.DuckDBPyRelation]

def hand_weights_v1(con: duckdb.DuckDBPyConnection, signals: str) -> duckdb.DuckDBPyRelation:
    ...

SCORERS: dict[str, Scorer] = {"hand_weights_v1": hand_weights_v1}

def score(con: duckdb.DuckDBPyConnection, signals: str, strategy: str) -> duckdb.DuckDBPyRelation:
    return SCORERS[strategy](con, signals)
```

- **The seam is the function type plus the dict.** No class hierarchy. A strategy may be Python, a SQL file or an LLM call inside; callers don't know.
- **Selected by name** from settings (`SCORER=hand_weights_v1`). An API endpoint may also take it as a parameter so two strategies can be compared side by side.
- **Every output row records the strategy name** (and the model id for LLM output). Results from different strategies must never mix unlabelled.
- **Once a strategy's output has been stored or evaluated, change its behaviour under a new key** (`_v2`). Keep the old one until its outputs are retired, so the two can be compared.
- **Seams go only at decision points:** attribution, signal weights, scoring, ranking, LLM labelling (provider, model, prompt). Parsing, storage, the API layer and settings get no seam.

### Python, FastAPI, Pydantic

- Type everything; `mypy --strict` runs on `pipeline/` and `api/`.
- Settings in one `pydantic-settings` class per process, read from env: `pipeline/settings.py` and `api/settings.py` (the app has no data root). No `os.environ` elsewhere, no hard-coded paths, model ids or weights.
- DuckDB is blocking: routes that query it are `def`, not `async def`, so FastAPI runs them in its thread pool.
- A DuckDB connection is not safe to share across threads. Open one read-only connection at startup and give each request its own `con.cursor()`.
- Response models are explicit Pydantic models. Don't return DuckDB rows or dicts from routes.

## Domain rules that are easy to get wrong

Each was a plausible rule the data disproved. Evidence and counts: `docs/eda/patterns.md` §7.

| Trap | Rule |
|---|---|
| CVE list on a record | Mostly inferred from the version string. **Only `verified` CVEs are evidence.** Never rank by CVE count |
| `kev` flag | Means "this version once had an exploited flaw". Use only with `verified`, or to catch same-day KEV additions |
| CDN-tagged records | Describe the CDN, not the customer. Excluded from exposure signals |
| Honeypot-tagged records | Dropped from every signal |
| `_shodan.module` (probe name) | Not the service. Use `product` and protocol objects |
| `org` / `isp` | Usually the hoster or carrier, not the company. Classify the owner first, then attribute |
| Hostname domain | Often ISP reverse DNS. Filter infrastructure domains computed from the file: IP-like hostnames (`179-125-1-1.provider.net`) and the dominant domain of ISP and hosting networks |
| DuckDB `count_if`, `least` | `count_if` gives NULL on all-NULL input; `least(NULL, 3)` is 3. Use `count(*) FILTER (WHERE …)` |
| Signals in general | Roll up from record to company. Collapse correlated evidence (an EOL nginx and its version CVEs are one fact) |

A new signal states its definition as code, its prevalence and its attributable coverage before it enters a score.

**No one labels or hand-checks data on an ongoing basis.** Never design a rule, check or metric that needs a person to label, and never add a static list drafted by an LLM as pipeline input. Classifications come from a named, dated source (scanner tags, PeeringDB, ASdb, the Public Suffix List) or a rule computed from the data, and the run log reports what each one covered.

**The one exception is the finding-score table.** No one on the team can judge security severity, so an LLM answers fixed factual questions per finding type (is it exploited, can it be automated, what does an attacker get) and a fixed table turns the answers into a score. It may be pipeline input only if:

- a `pipeline ref` command produces it from a versioned prompt; it is never typed or edited by hand
- it covers distinct finding types, never records
- every row records the strategy, prompt version, model, how it was run (API or Claude Code) and the date
- the model's answers are checked against an outside source (KEV, EPSS) and against a second model, and the agreement is reported

A finding type with no row is unscored, never guessed.

## LLM use

- Label **distinct values** (org strings, domains, titles), never raw records. Cache by `(strategy, model, input hash)`, so cost grows with new values, not with volume.
- Validate every response against a Pydantic model; anything that fails validation is recorded as unlabelled, never guessed.
- Before an LLM labeller is used, measure its agreement with an independent source (for network types, PeeringDB). Record the agreement rate, and the tokens and cost per 1,000 items.
- Model id, prompt and provider come from settings, behind the rule 3 registry.
- **Each use case reads its model from its own `<USE_CASE>_MODEL` setting,** defaulting to `claude-haiku-5-5`, the only model the API key can call. A new use case adds its variable when it's built.
- **Every API call writes one row to `llm_usage/calls.jsonl` through `llm_usage.record`, failures included.** A refused or cut-off reply is still billed. No code path calls the Anthropic API without writing its row.
- A model with no row in the price table (`llm_prices` in `pipeline/settings.py`) gets an empty cost, never a guess.

## Tests

A test earns its place by catching a bug that would put a wrong company at the top of the list, or hide a real one.

- **Earns a test:** noise filters (each built from the real record that motivated it), attribution routes, scoring and ranking order, switching strategy by config, idempotent re-runs of a file, LLM response validation.
- **Doesn't:** Pydantic or FastAPI behaviour, getters, mocks asserting on mocks, one test per branch.
- Prefer one test through the real pipeline on a small fixture over many unit tests on helpers. Fixtures are a few real records copied from the sample.

## Claims and numbers

- Every number in `docs/` or the write-up comes from a script or query you can name, run on a named input. If you didn't measure it, it doesn't appear.
- Keep verified, inferred and assumed apart, and label which is which.
- Hand weights and thresholds are assumptions until validated. Say so wherever they are presented.
