# Who needs cybersecurity help right now

A sales tool for a cybersecurity vendor. It turns one Shodan scan file (17.6 GB, 14.6 million records) into a ranked list of companies with a security problem visible from the internet. Each company comes with the evidence a salesperson can open the conversation with.

**App:** _link added after deploy_. The login is shared separately.

## What a salesperson gets

- **A ranked list of 8,092 companies,** worst problem first. Filters: "High confidence only", "Would give an attacker full control", "Attackers use this kind of hole", "Signs of a break-in", by problem type, and a search. Exports to CSV.
- **A company page:**
  - every problem found, worst first
  - the scanner's reply that proves it
  - one plain sentence on what it means
  - how sure we are it's this company, and why
- **A "How we know" page:** the checks in [`docs/evaluation.md`](docs/evaluation.md).

## Approach

**Find** the problem in the reply → **score** how bad that kind of problem is → **attribute** the service to a company → **rank** the companies. Details and every number: [`docs/signals.md`](docs/signals.md).

The pipeline that does this on each scan file is in [`docs/pipeline.md`](docs/pipeline.md). Bronze, silver and gold are layers over DuckDB and Parquet. One file takes about 7 minutes on one laptop.

## Key decisions

| Decision | Why |
|---|---|
| **A signal is something the reply shows,** never the scanner's guess | Only 6,111 of 20,988,468 CVE entries on the records were tested by the scanner. The rest are looked up from a version string ([`docs/eda/blind-analysis.md`](docs/eda/blind-analysis.md) §3) |
| **The first analysis was re-done blind before anything was built on it** | An independent pass over the raw tables, without reading the first one's conclusions, tested each rule instead of inheriting it. It rated 53 candidate signals against real replies and recorded why each rejected one failed |
| **Attribute before scoring, and leave out what can't be named** | Most addresses belong to a hoster, ISP or cloud, not the business. A guessed company is worse than no company, so each company carries a confidence and the clue it came from |
| **A model answers fixed factual questions per finding type; a fixed table turns answers into a score** | No one on the team can judge security severity. 68 answers cover the whole file, and gold never calls a model. The answers are checked against CISA's KEV list, FIRST's EPSS scores and two other models. The larger models refused the prompt until it stated the tool's defensive purpose ([`docs/evaluation.md`](docs/evaluation.md) §2) |
| **Rank by a company's worst finding × confidence** | An attacker needs one hole. The rule can't double-count one fault reported two ways, and doesn't push a company up for being big. A rule that sums findings runs beside it for comparison |
| **No hand labels, and no AI-drafted lists as input** | No one on the team can keep labelling. Classifications come from dated public sources: scanner tags, PeeringDB, ASdb, the Public Suffix List |
| **Every guess is a named, swappable strategy** | Attribution, scoring and ranking are plain functions chosen by name from settings, and every output row records which one made it. A second strategy runs beside the first; it never overwrites it |

## How we know it works

From [`docs/evaluation.md`](docs/evaluation.md):

| What | Result |
|---|---|
| Attribution on 256 synthetic test services | 213 right, 40 missed, **3 wrong** |
| Opus's "actively exploited" against CISA's KEV list | 19 agree that it's exploited, 10 agree that it isn't, 2 Opus only, 0 KEV only |
| Sonnet and Haiku against Opus, three questions × 66 types | 57–64 of 66 agree |
| The two ranking rules | share 12 of their top 100 companies |
| Past ransomware victims (Ransomware.live) | 6 matched, shown as an illustration, not a measurement |
| Model cost, one run over all 68 finding types | Haiku **$0.0229** · Sonnet **$0.31** · Opus **$0.71** |

**The synthetic cases were written by AI** with answers known by construction. They test the rules on shapes we thought of, not precision on real data. **No ranking can be proven right** without knowing who gets breached next.

## Limits

- **Only 12.3% of services with a finding can be tied to a company** (10,005 of 81,554). Most of the rest sit on ISP, hosting and cloud networks with no website name.
- **No contact person.** The scan has no people in it, so "how do they reach them first" stops at the company domain and the evidence. Contacts would come from the buyer's own data provider.
- **No company size or industry.** Neither is in the scan.
- **The score table and the confidence weights were drafted by AI and aren't validated.**
- **Shared hosting leaks through attribution:** some hosters still appear as companies ([`docs/signals.md`](docs/signals.md) §4).
- **Many companies tie on score,** so tie-breaks decide much of the order ([`docs/signals.md`](docs/signals.md) §5).
- **One file covers about 19 hours of scanning.** "New since last time" needs a second file and isn't built.

## How I worked with AI

The loop is built to stop an agent from being confidently wrong:

- **Rules the agent works under,** in [`CLAUDE.md`](CLAUDE.md): the data traps measured so far, no abstraction until a second use, what earns a test, and a source for every number.
- **Measure before a full run.** A failure is reproduced on a 2-million-line slice of the raw file with memory logging and fixed there. Then the full file runs once.
- **Every layer is planned and agreed before it's built,** and runs on the sample before the full file.
- **Checks on every write and build:** ruff through a hook (`.claude/`), `mypy --strict`, and the pipeline's blocking checks.
- **Every model API call is logged** to `llm_usage/calls.jsonl`, failures included.

## Run it

Needs Python 3.12, [`uv`](https://docs.astral.sh/uv/), `zstd` and the scan file in `data/raw/`.

```sh
uv sync

# A 1-in-400 sample of the scan
zstd -dc data/raw/<scan file> | uv run python archive/scripts/eda/stride_sample.py 400 data/samples/stride400.jsonl

# Reference data
uv run python -m pipeline ref peeringdb
#   ASdb: download a snapshot from asdb.stanford.edu into data/ref/asdb/as_of=<YYYY-MM>/
#   KEV and EPSS: save CISA's KEV JSON as data/external/kev.json
#   and FIRST's daily EPSS CSV as data/external/epss_scores-current.csv.gz

# Pipeline on the sample, then make it the scan the app shows
export DATA_ROOT=data/runs/sample
uv run python -m pipeline bronze data/samples/stride400.jsonl
uv run python -m pipeline silver data/samples/stride400.jsonl
uv run python -m pipeline gold   data/samples/stride400.jsonl
uv run python -m pipeline eval attribution            # the reports "How we know" shows
uv run python -m pipeline ref finding-scores check
uv run python -m pipeline publish data/samples/stride400.jsonl

# The app: set APP_USERS (from `uv run python -m api hash-password`), SESSION_SECRET
# and COOKIE_SECURE=false in .env
uv run uvicorn api.main:create_app --factory --reload

uv run pytest
```

| Path | What it is |
|---|---|
| `pipeline/` | Landing → bronze → silver → gold → publish, and the `pipeline` CLI |
| `api/` | The FastAPI app and its Jinja2 + HTMX pages. Reads only `data/publish/` |
| `finding_scores/` | The models' validated answers per finding type, which gold scores with |
| `llm_usage/` | One row per model API call, and the totals |
| `tests/` | Tests, and the synthetic attribution cases in `tests/eval/` |
| `docs/` | What the data contains, the signals, the pipeline and the evaluation |
| `archive/` | Frozen exploration scripts that reproduce the numbers in `docs/eda/` and `docs/terms.md` |
