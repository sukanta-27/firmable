import csv
import io
from typing import Annotated, Any, Literal

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from api.db import cursor
from api.settings import ApiSettings

router = APIRouter()

# "Signs of a break-in": the only finding types that say something has happened, not just
# that an attacker could get in.
BREACH_TYPES = ["ransom_note", "tag_compromised"]


class Filters(BaseModel):
    scorer: str | None = None
    confidence: list[Literal["High", "Medium", "Low"]] = []
    finding_type: list[str] = []
    attacked_in_the_wild: bool = False
    could_give_full_control: bool = False
    already_breached: bool = False
    q: str | None = None


class Page(Filters):
    limit: int = Field(50, ge=1, le=200)
    offset: int = Field(0, ge=0)


class WorstFinding(BaseModel):
    finding_type: str
    salesperson_line: str | None
    score: int | None


class CompanyRow(BaseModel):
    rank: int | None
    company_key: str
    company_kind: str
    company_name: str | None
    ranking_score: float | None
    company_score: float | None
    confidence: str
    confidence_route: str | None
    distinct_finding_types: int
    services_with_finding: int
    finding_share: float
    worst_finding: WorstFinding | None


class CompanyList(BaseModel):
    total: int
    scorer: str
    file_id: str
    items: list[CompanyRow]


def chosen_scorer(request: Request, scorer: str | None) -> str:
    settings: ApiSettings = request.app.state.settings
    chosen = scorer or settings.company_scorer
    if chosen not in request.app.state.scan.scorers:
        raise HTTPException(status_code=422, detail=f"unknown scorer {chosen}")
    return chosen


def matching(
    cur: duckdb.DuckDBPyConnection, filters: Filters, scorer: str
) -> duckdb.DuckDBPyRelation:
    """The companies that pass every filter, in gold's rank order, unranked ones last."""
    where = ["c.company_scorer = $scorer"]
    params: dict[str, Any] = {"scorer": scorer}
    has = "EXISTS (SELECT 1 FROM company_finding f WHERE f.company_key = c.company_key AND {})"
    if filters.confidence:
        where.append("list_contains($confidence, c.confidence)")
        params["confidence"] = filters.confidence
    if filters.finding_type:
        where.append(has.format("list_contains($finding_type, f.finding_type)"))
        params["finding_type"] = filters.finding_type
    if filters.attacked_in_the_wild:
        where.append(has.format("f.exploitation_final = 'active'"))
    if filters.could_give_full_control:
        where.append(has.format("f.severity = 3"))
    if filters.already_breached:
        where.append(has.format("list_contains($breach_types, f.finding_type)"))
        params["breach_types"] = BREACH_TYPES
    if filters.q:
        where.append(
            "(contains(lower(c.company_key), lower($q)) "
            "OR contains(lower(coalesce(c.company_name, '')), lower($q)))"
        )
        params["q"] = filters.q
    return cur.sql(
        f"""
        SELECT c.rank, c.company_key, c.company_kind, c.company_name, c.ranking_score,
          c.company_score, c.confidence, c.confidence_route, c.distinct_finding_types,
          c.services_with_finding, c.finding_share, c.top_finding_type,
          (SELECT any_value(f.salesperson_line) FROM company_finding f
           WHERE f.company_key = c.company_key AND f.finding_type = c.top_finding_type)
            AS top_line,
          (SELECT max(f.score) FROM company_finding f
           WHERE f.company_key = c.company_key AND f.finding_type = c.top_finding_type)
            AS top_score
        FROM company c
        WHERE {" AND ".join(where)}
        ORDER BY c.rank NULLS LAST, c.company_key
        """,
        params=params,
    )


def as_row(r: tuple[Any, ...]) -> CompanyRow:
    (rank, key, kind, name, ranking, score, confidence, route, types, services, share,
     top_type, top_line, top_score) = r  # fmt: skip
    return CompanyRow(
        rank=rank,
        company_key=key,
        company_kind=kind,
        company_name=name,
        ranking_score=ranking,
        company_score=score,
        confidence=confidence,
        confidence_route=route,
        distinct_finding_types=types,
        services_with_finding=services,
        finding_share=share,
        worst_finding=WorstFinding(
            finding_type=top_type, salesperson_line=top_line, score=top_score
        )
        if top_type
        else None,
    )


@router.get("/companies")
def list_companies(
    request: Request,
    page: Annotated[Page, Query()],
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> CompanyList:
    scorer = chosen_scorer(request, page.scorer)
    found = matching(cur, page, scorer)
    (total,) = found.count("*").fetchall()[0]
    rows = found.limit(page.limit, offset=page.offset).fetchall()
    return CompanyList(
        total=total,
        scorer=scorer,
        file_id=request.app.state.scan.file_id,
        items=[as_row(r) for r in rows],
    )


CSV_COLUMNS = [
    "rank", "company_key", "company_kind", "company_name", "ranking_score", "company_score",
    "confidence", "confidence_route", "distinct_finding_types", "services_with_finding",
    "finding_share", "worst_finding_type", "worst_finding_line", "worst_finding_score",
    "scorer", "file_id",
]  # fmt: skip


def spreadsheet_safe(value: object) -> object:
    # Company names come from scan `org` strings. Excel and Sheets run a cell starting with
    # one of these as a formula when a rep opens the file (OWASP "CSV injection").
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


@router.get("/companies.csv")
def export_companies(
    request: Request,
    filters: Annotated[Filters, Query()],
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> Response:
    scorer = chosen_scorer(request, filters.scorer)
    scan = request.app.state.scan
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for r in matching(cur, filters, scorer).fetchall():
        row = as_row(r)
        worst = row.worst_finding
        writer.writerow(
            spreadsheet_safe(v)
            for v in (
                *row.model_dump(exclude={"worst_finding"}).values(),
                worst.finding_type if worst else None,
                worst.salesperson_line if worst else None,
                worst.score if worst else None,
                scorer,
                scan.file_id,
            )
        )
    filename = f"companies_{scan.received_at.date().isoformat()}_{scorer}.csv"
    return Response(
        out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
