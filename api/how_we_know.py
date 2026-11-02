import json
from datetime import datetime
from pathlib import Path
from typing import Literal, Self

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.reports import AnswersCheck, AttributionReport, RankingReport, UsageReport
from api.settings import ApiSettings

router = APIRouter()


class Section[R: BaseModel](BaseModel):
    status: Literal["ok", "not_run"]
    # Named even when not run, so the page can say what would produce it.
    command: str
    report: R | None

    @classmethod
    def of(cls, command: str, report: R | None) -> Self:
        return cls(status="not_run" if report is None else "ok", command=command, report=report)


class Coverage(BaseModel):
    command: str
    ran_at: datetime
    # Services attributed or unknown, by confidence and by route; `all` counts every
    # service, `with_signal` only those with a finding.
    metrics: dict[str, int]


class HowWeKnow(BaseModel):
    attribution_coverage: Coverage
    attribution_cases: Section[AttributionReport]
    finding_scores: Section[AnswersCheck]
    ranking: Section[RankingReport]
    llm_usage: Section[UsageReport]


def _read[R: BaseModel](path: Path, model: type[R]) -> R | None:
    return model.model_validate_json(path.read_text()) if path.exists() else None


@router.get("/how-we-know")
def how_we_know(request: Request) -> HowWeKnow:
    """The evidence behind the list: each eval report the published scan carries, with the
    command and date that produced it."""
    settings: ApiSettings = request.app.state.settings
    root = settings.publish_root
    run = json.loads((root / "gold_run.json").read_text())
    reports = root / "eval"
    return HowWeKnow(
        attribution_coverage=Coverage(
            command="pipeline gold",
            ran_at=run["finished_at"],
            metrics={
                k.removeprefix("attribution."): v
                for k, v in run["metrics"].items()
                if k.startswith("attribution.")
            },
        ),
        attribution_cases=Section[AttributionReport].of(
            "pipeline eval attribution",
            _read(reports / "attribution.json", AttributionReport),
        ),
        finding_scores=Section[AnswersCheck].of(
            "pipeline ref finding-scores check",
            _read(reports / "finding_scores_check.json", AnswersCheck),
        ),
        ranking=Section[RankingReport].of(
            "pipeline eval ranking <source>",
            _read(reports / "ranking.json", RankingReport),
        ),
        llm_usage=Section[UsageReport].of(
            "pipeline ref llm-usage", _read(reports / "llm_usage.json", UsageReport)
        ),
    )
