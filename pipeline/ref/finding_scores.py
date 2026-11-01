"""The finding-score answers: an AI answers fixed factual questions per finding type.

Render writes the prompt from the data (git-ignored, because it quotes real scan replies).
The owner runs it in Claude Code from an empty folder, or `ask` sends it through the API.
Import validates every answer and rewrites the committed answers file; anything that fails
is recorded as unscored, never repaired or guessed. Gold reads that file and never calls a
model. The prompt is blind on purpose: no KEV, EPSS, CVSS, counts or our own risk split,
because `check` compares the answers against exactly those.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import anthropic
import duckdb
from pydantic import BaseModel, ConfigDict, ValidationError

from pipeline.settings import RefSettings, Settings
from pipeline.silver.signal_rules import DESCRIPTIONS, RULES

PROMPTS = Path(__file__).parent
EVIDENCE_PER_ITEM = 2
EVIDENCE_CHARS = 300


class Item(BaseModel):
    item_id: str
    kind: Literal["exposure", "vulnerability"]
    description: str
    evidence: list[str]


class ModelAnswer(BaseModel):
    # Strict, so "answerable": "no" or 1 is invalid rather than coerced into a boolean.
    model_config = ConfigDict(strict=True)

    item_id: str
    answerable: bool
    exploitation: Literal["active", "poc", "none"] | None
    automatable: Literal["yes", "no"] | None
    technical_impact: Literal["total", "partial", "information"] | None
    reason: str
    salesperson_line: str


class Answer(BaseModel):
    item_id: str
    kind: Literal["exposure", "vulnerability"]
    status: Literal["answered", "unanswerable", "invalid"]
    exploitation: Literal["active", "poc", "none"] | None = None
    automatable: Literal["yes", "no"] | None = None
    technical_impact: Literal["total", "partial", "information"] | None = None
    reason: str | None = None
    salesperson_line: str | None = None
    model: str
    prompt_version: str
    run_via: Literal["claude_code", "api"]
    run_date: str
    input_hash: str


def read_answers(path: Path) -> list[Answer]:
    if not path.exists():
        return []
    return [Answer.model_validate_json(line) for line in path.read_text().splitlines() if line]


def without_exploitation_claims(summary: str) -> str:
    """A CVE summary minus what it says about attacks in the wild, which is the exploitation
    answer the model must give blind: 14 summaries in the 2026-10-26 file say it, either as a
    trailing clause (", as exploited in the wild in July 2013") or as a sentence."""
    summary = re.sub(r",\s*as exploited in the wild[^.]*", "", summary, flags=re.IGNORECASE)
    sentences = re.split(r"(?<=[.!?])\s+", summary.strip())
    return " ".join(s for s in sentences if "in the wild" not in s.lower())


def render(settings: Settings, limit: int | None = None) -> Path:
    """Write today's prompt for every finding type the data holds that has no answer yet."""
    silver, bronze = settings.data_root / "silver", settings.data_root / "bronze"
    con = duckdb.connect()
    evidence = {
        code: texts
        for code, texts in con.execute(
            f"""
            SELECT signal_code, list(t ORDER BY first_key)[1:{EVIDENCE_PER_ITEM}]
            FROM (
              SELECT signal_code, left(evidence_text, {EVIDENCE_CHARS}) AS t,
                min(service_key) AS first_key
              FROM read_parquet('{silver}/service_signal/*/*.parquet')
              WHERE coalesce(evidence_text, '') <> ''
              GROUP BY ALL
            )
            GROUP BY 1
            """
        ).fetchall()
    }
    # The same eligibility gold applies: CDN and noise services are never scored.
    vulns = con.execute(
        f"""
        SELECT v.cve, any_value(t.summary)
        FROM read_parquet('{silver}/service_vuln/*/*.parquet') v
        JOIN read_parquet('{silver}/service/*/*.parquet') s USING (service_key)
        JOIN read_parquet('{silver}/address/*/*.parquet') a ON a.ip = s.ip
        LEFT JOIN read_parquet('{bronze}/cve_text/*/*.parquet') t ON t.cve = v.cve
        WHERE v.verified AND s.noise_reason IS NULL AND a.owner_class IS DISTINCT FROM 'cdn'
        GROUP BY 1 ORDER BY 1
        """
    ).fetchall()
    missing = [code for code in RULES if code not in DESCRIPTIONS]
    if missing:
        raise ValueError(f"signal codes without a description: {missing}")
    items = [
        Item(item_id=c, kind="exposure", description=DESCRIPTIONS[c], evidence=evidence.get(c, []))
        for c in RULES
    ] + [
        Item(
            item_id=cve,
            kind="vulnerability",
            description=without_exploitation_claims(summary or cve),
            evidence=[],
        )
        for cve, summary in vulns
    ]
    done = {
        a.item_id
        for a in read_answers(settings.answers_path)
        if a.status == "answered"
        and a.model == settings.answers_model
        and a.prompt_version == settings.prompt_version
    }
    items = [i for i in items if i.item_id not in done][:limit]

    target = (
        settings.ref_root
        / "finding_scores"
        / f"prompt_{settings.prompt_version}"
        / datetime.now(UTC).date().isoformat()
    )
    target.mkdir(parents=True, exist_ok=True)
    items_json = json.dumps([i.model_dump() for i in items], indent=1, ensure_ascii=False)
    (target / "items.json").write_text(items_json + "\n")
    template = (PROMPTS / f"finding_score_prompt_{settings.prompt_version}.md").read_text()
    (target / "prompt.md").write_text(template.replace("ITEMS_JSON", items_json))
    return target


def newest_render(settings: RefSettings) -> Path:
    found = sorted(
        (settings.ref_root / "finding_scores" / f"prompt_{settings.prompt_version}").glob("*")
    )
    if not found:
        raise FileNotFoundError(
            "no rendered prompt; run `pipeline ref finding-scores render` first"
        )
    return found[-1]


def _parse(text: str) -> list[object] | None:
    """The response's JSON array, allowing one fenced code block around it and nothing else."""
    fenced = re.fullmatch(r"```(?:json)?\s*\n(.*)\n```", text.strip(), re.S)
    try:
        parsed = json.loads(fenced.group(1) if fenced else text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, list) else None


def import_answers(
    settings: RefSettings,
    response: Path,
    model: str,
    run_via: Literal["claude_code", "api"],
    render_dir: Path | None = None,
) -> Counter[str]:
    """Validate a model's response against its render and rewrite the answers file.

    Rows for this model, prompt version and the render's items are replaced; every other
    row is kept, so a re-import is idempotent and a later render only adds new items.
    """
    render_dir = render_dir or newest_render(settings)
    items_bytes = (render_dir / "items.json").read_bytes()
    kinds = {i["item_id"]: i["kind"] for i in json.loads(items_bytes)}
    stamp = {
        "model": model,
        "prompt_version": settings.prompt_version,
        "run_via": run_via,
        "run_date": datetime.now(UTC).date().isoformat(),
        "input_hash": hashlib.sha256(items_bytes).hexdigest(),
    }
    counts: Counter[str] = Counter()
    answered: dict[str, Answer] = {}
    for element in _parse(response.read_text()) or []:
        item_id = element.get("item_id") if isinstance(element, dict) else None
        if not isinstance(item_id, str) or item_id not in kinds:
            counts["unknown_item"] += 1
            continue
        if item_id in answered:
            # Two answers for one item: keeping either would be choosing for the model.
            counts["duplicate_item"] += 1
            answered[item_id] = Answer(
                item_id=item_id, kind=kinds[item_id], status="invalid", **stamp
            )
            continue
        try:
            got = ModelAnswer.model_validate(element)
        except ValidationError:
            answered[item_id] = Answer(
                item_id=item_id, kind=kinds[item_id], status="invalid", **stamp
            )
            continue
        three = (got.exploitation, got.automatable, got.technical_impact)
        if not got.answerable:
            status = "unanswerable"
        else:
            status = "answered" if None not in three else "invalid"
        answered[item_id] = Answer(
            item_id=item_id,
            kind=kinds[item_id],
            status=status,
            **(
                got.model_dump(include={"exploitation", "automatable", "technical_impact"})
                if status == "answered"
                else {}
            ),
            reason=got.reason,
            salesperson_line=got.salesperson_line if status == "answered" else None,
            **stamp,
        )
    for item_id, kind in kinds.items():
        answered.setdefault(item_id, Answer(item_id=item_id, kind=kind, status="invalid", **stamp))
    counts.update(a.status for a in answered.values())

    kept = [
        a
        for a in read_answers(settings.answers_path)
        if not (
            a.model == model and a.prompt_version == settings.prompt_version and a.item_id in kinds
        )
    ]
    rows = sorted(
        [*kept, *answered.values()], key=lambda a: (a.prompt_version, a.model, a.kind, a.item_id)
    )
    settings.answers_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings.answers_path.with_suffix(".tmp")
    tmp.write_text("".join(a.model_dump_json() + "\n" for a in rows))
    tmp.replace(settings.answers_path)
    return counts


type AnswerProvider = Callable[[RefSettings, Path, str], Path]


def anthropic_messages(settings: RefSettings, render_dir: Path, model: str) -> Path:
    """Send the rendered prompt as one request and save the raw reply beside it. Untested
    until the owner's smoke test: no agent session may spend on it.

    No server-side refusal fallback: a fallback model's answers would be stored under the
    model asked for. A refusal or a cut-off reply raises, and nothing is imported.
    """
    key = settings.anthropic_api_key
    client = anthropic.Anthropic(api_key=key.get_secret_value() if key else None)
    with client.messages.stream(
        model=model,
        max_tokens=64000,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        messages=[{"role": "user", "content": (render_dir / "prompt.md").read_text()}],
    ) as stream:
        message = stream.get_final_message()
    if message.stop_reason != "end_turn":
        raise RuntimeError(f"{model} stopped with {message.stop_reason}; nothing imported")
    target = render_dir / f"response_{model}.json"
    target.write_text("".join(b.text for b in message.content if b.type == "text"))
    return target


ANSWER_PROVIDERS: dict[str, AnswerProvider] = {"api": anthropic_messages}
