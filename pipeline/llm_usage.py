"""One row per LLM API call, failures included, and the totals over them.

Every code path that calls the Anthropic API writes its row through `record`, whatever the
outcome: a refused or cut-off reply is still billed, so a log of successes alone
under-reports the cost.
"""

import hashlib
import statistics
from datetime import UTC, datetime
from typing import Literal

from anthropic.types import Usage
from pydantic import BaseModel

from api.reports import UsageReport, UsageTotal
from pipeline.meta import report_stamp, write_json
from pipeline.settings import RefSettings

type CallKind = Literal["messages", "count_tokens"]
SUCCESS = {"messages": "end_turn", "count_tokens": "ok"}


class Call(BaseModel):
    timestamp: str
    use_case: str
    model: str
    provider: Literal["anthropic"]
    kind: CallKind
    # The stop reason, "ok" for a token count, or the exception class when the call raised.
    outcome: str
    request_id: str | None
    input_tokens: int | None
    output_tokens: int | None
    cache_write_tokens: int | None
    cache_read_tokens: int | None
    seconds: float
    input_price_per_mtok: float | None
    output_price_per_mtok: float | None
    price_source: str | None
    cost_usd: float | None
    prompt_version: str
    input_hash: str
    items: int


def _cost(settings: RefSettings, model: str, kind: CallKind, usage: Usage | None) -> float | None:
    price = settings.llm_prices.get(model)
    if kind != "messages" or usage is None or price is None:
        return None
    # No cache prices in the table yet, so a call that used the cache isn't priced at all.
    if usage.cache_creation_input_tokens or usage.cache_read_input_tokens:
        return None
    if price.up_to_input_tokens is not None and usage.input_tokens > price.up_to_input_tokens:
        return None
    return (
        usage.input_tokens * price.input_per_mtok + usage.output_tokens * price.output_per_mtok
    ) / 1_000_000


def record(
    settings: RefSettings,
    *,
    use_case: str,
    model: str,
    kind: CallKind,
    outcome: str,
    request_id: str | None,
    usage: Usage | None,
    input_tokens: int | None = None,
    seconds: float,
    prompt_version: str,
    input_hash: str,
    items: int,
) -> Call:
    """Append one call. `usage` comes from a message; a token count passes `input_tokens`."""
    price = settings.llm_prices.get(model)
    priced = kind == "messages" and price is not None
    call = Call(
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
        use_case=use_case,
        model=model,
        provider="anthropic",
        kind=kind,
        outcome=outcome,
        request_id=request_id,
        input_tokens=usage.input_tokens if usage else input_tokens,
        output_tokens=usage.output_tokens if usage else None,
        cache_write_tokens=usage.cache_creation_input_tokens if usage else None,
        cache_read_tokens=usage.cache_read_input_tokens if usage else None,
        seconds=round(seconds, 2),
        input_price_per_mtok=price.input_per_mtok if priced and price else None,
        output_price_per_mtok=price.output_per_mtok if priced and price else None,
        price_source=settings.llm_price_source if priced else None,
        cost_usd=_cost(settings, model, kind, usage),
        prompt_version=prompt_version,
        input_hash=input_hash,
        items=items,
    )
    settings.llm_usage_path.parent.mkdir(parents=True, exist_ok=True)
    with settings.llm_usage_path.open("a") as f:
        f.write(call.model_dump_json() + "\n")
    return call


def summarise(settings: RefSettings) -> UsageReport:
    path = settings.llm_usage_path
    calls = (
        [Call.model_validate_json(line) for line in path.read_text().splitlines() if line]
        if path.exists()
        else []
    )
    groups: dict[tuple[str, str, CallKind], list[Call]] = {}
    for c in calls:
        groups.setdefault((c.use_case, c.model, c.kind), []).append(c)
    totals = [
        UsageTotal(
            use_case=use_case,
            model=model,
            kind=kind,
            calls=len(rows),
            failures=sum(r.outcome != SUCCESS[kind] for r in rows),
            input_tokens=sum(r.input_tokens or 0 for r in rows),
            output_tokens=sum(r.output_tokens or 0 for r in rows),
            cache_write_tokens=sum(r.cache_write_tokens or 0 for r in rows),
            cache_read_tokens=sum(r.cache_read_tokens or 0 for r in rows),
            cost_usd=(
                sum(r.cost_usd or 0.0 for r in rows)
                if any(r.cost_usd is not None for r in rows)
                else None
            ),
            unpriced_calls=sum(r.cost_usd is None for r in rows),
            median_seconds=statistics.median(r.seconds for r in rows),
        )
        for (use_case, model, kind), rows in sorted(groups.items())
    ]
    log_hash = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "none"
    report = UsageReport(
        stamp=report_stamp("pipeline ref llm-usage", log=str(path), log_sha256=log_hash),
        totals=totals,
    )
    write_json(settings.llm_usage_report, report)
    return report
