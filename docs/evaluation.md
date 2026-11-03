# How we know it works, and where it doesn't

**There is no labelled answer key for this data, and no one on the team labels or hand-checks records.** So each guess the pipeline makes is checked against something outside it: synthetic cases with known answers, public exploit lists, a second and third model, and past ransomware victims. Every number below is in a report the pipeline writes and the app's "How we know" page serves: `data/publish/eval/*.json`, made by the commands named in each section.

## 1. Attribution: synthetic cases

`uv run python -m pipeline eval attribution` scores `rules_ab_v1` on `tests/eval/attribution_cases.json`.

**The cases are synthetic.** AI wrote 17 made-up situations in silver's table shapes, most modelled on a pattern measured in the real file. The right answer is known because the situation was constructed. They show the rules do what was intended on the shapes we thought of. **They don't measure precision on real data.**

| | Services |
|---|---|
| Right company named, or rightly no company | **213** of 256 |
| Missed: no company named when there was one | **40** |
| Wrong: the wrong company named | **3** |

**The two cases that fail, both known and not fixed:**
- **`cloud_customer_fleet`, 40 missed.** A company names 40 cloud servers under its own domain. Rule A sees the same spread a hoster's naming has and drops the domain. A miss, not a wrong name: the company is left out rather than misnamed.
- **`template_directory_name`, 3 wrong at High.** Directory servers on three unrelated networks report the same generic name left over from a setup template (`local.net`). It gets named as a company. Names like `group.org` and `global.io` do this on the real file, on 3–5 networks each.

## 2. Finding scores: do the models' answers hold up?

`uv run python -m pipeline ref finding-scores check`

**Three models answered the same questions** for all 68 finding types. The prompt is [`pipeline/ref/finding_score_prompt_v1.md`](../pipeline/ref/finding_score_prompt_v1.md). Each of the 68 types comes with a plain description and excerpts of real scanner replies as evidence. The Claude Code runs started from an empty folder, so the model saw nothing of this repository. The rendered prompt and each model's raw reply are in [`prompts/finding-scores-v1/`](prompts/finding-scores-v1/): `prompt.md` is what Haiku answered, and `prompt-with-purpose.md` adds the purpose paragraph described below.

| Model | How it ran | Answered | Role |
|---|---|---|---|
| Claude Opus 5.5 | Claude Code | 66, plus 2 it called unanswerable | **Gold scores with these answers** |
| Claude Sonnet 5.5 | Claude Code | 68 | Second opinion |
| Claude Haiku 5.5 | API | 68 | Third opinion |

**The prompt is blind on purpose.** It holds no KEV, EPSS, CVSS or counts, because the check compares the answers against exactly those (`pipeline/ref/finding_scores.py`). **The larger models refused the bare prompt.** Asked how exploitable a list of exposed services is, Opus and Sonnet declined ([Opus's reply](prompts/finding-scores-v1/response_claude-opus-5-5.refused.json)). Stating the purpose first got both to answer: defensive triage, so the affected businesses hear about it before an attacker does. Their stored answers come from v1 with a paragraph like that at the top. [`pipeline/ref/finding_score_prompt_v2.md`](../pipeline/ref/finding_score_prompt_v2.md) is v1 plus that paragraph. The questions and the 68 items are unchanged, so the three models' answers compare directly. Haiku answered v1 as it is.

**Against CISA's KEV catalog** (2026.10.27), for the CVEs each model answered: does the model say "actively exploited" when KEV lists the CVE?

| Model | Both say exploited | Model only | KEV only | Neither |
|---|---|---|---|---|
| Opus | 19 | 2 | 0 | 10 |
| Sonnet | 18 | 1 | 1 | 12 |
| Haiku | 15 | 1 | 4 | 12 |

**Against FIRST's EPSS** (scored 2026-10-27), the median exploit probability by Opus's answer: 0.999 for "active" (21 CVEs) and 0.452 for "proof of concept" (10).

**Between models,** each compared with Opus on the 66 types Opus answered:

| Question | Sonnet agrees | Haiku agrees |
|---|---|---|
| Is it exploited? | 59 | 58 |
| Can it be automated? | 59 | 64 |
| What does an attacker get? | 58 | 57 |

**Caveat: the KEV check measures recall more than judgement.** Both Claude Code models cite the KEV list from memory in their reasons. Sonnet wrongly claims CVE-2023-23333 is on it; the 2026-10-27 catalog doesn't list it. Gold doesn't depend on the model here: a KEV listing overrides the model's exploitation answer.

## 3. Ranking: no outcome to measure against

**No test can show a ranking is right without knowing who gets breached next.** A synthetic "right order" would only write down our own preference. So the ranking report (`uv run python -m pipeline eval ranking <source>`) gives a reader what they need to judge it:

- **The two rules share 12 of their top 100 companies.** The default takes each company's worst finding; the comparison rule sums all of them.
- **Past ransomware victims, as an illustration, not a measurement.** 8,676 victim domains from Ransomware.live (as of 2026-10-31) match **6** companies in the list. Under the sum rule they rank 104, 1,403, 1,560, 4,034, 7,872 and 8,081 of 8,092. This looks backwards: it says where past victims sat when scanned, not whether the ranking predicts the next one. Source: [Ransomware.live](https://www.ransomware.live).

## 4. What the models cost

`uv run python -m pipeline ref llm-usage` totals `llm_usage/calls.jsonl`, which gets one row per API call, failures included.

One run answers all 68 finding types:

| Model | Input tokens | Output tokens | Time | Cost | Per 1,000 finding types |
|---|---|---|---|---|---|
| Haiku 5.5 | 19,360 | 41,934 | 181 s | **$0.0229** | $0.34 |
| Sonnet 5.5 | 19,482 | 26,815 | 195 s | **$0.3071** | $4.52 |
| Opus 5.5 | 19,400 | 31,500 | 212 s | **$0.7076** | $10.41 |

- **Prices** per million input / output tokens: Haiku 5.5 $0.10 / $0.50 for prompts up to 100K tokens, Sonnet 5.5 $2 / $10, Opus 5.5 $4 / $20 ([claude.com/pricing](https://claude.com/pricing), checked 2026-11-03).
- **A refused call is still billed:** $0.09–$0.11 each here.
- Opus's tokens were recorded outside `calls.jsonl`.
- **Cost grows with distinct finding types, not with scan volume.** The model answers once per type, and gold reads the stored answers without calling a model. A thousand more files of the same kinds of findings cost nothing more.

## 5. Tests

`uv run pytest`: 48 tests. They aim at what would put a wrong company at the top or hide a real one:
- every record landing exactly once, and reruns replacing rather than duplicating
- noise filters, each built from a real record
- attribution rules and the synthetic cases
- ranking order and its tie-breaks
- strict validation of the models' answers, and a cost-only model call that can't change the stored answers
- login, sessions and lockout
- CSV cells that can't run as spreadsheet formulas
