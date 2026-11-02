from datetime import datetime
from itertools import groupby
from typing import Annotated

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.companies import CompanyRow, Filters, as_row, chosen_scorer, matching
from api.db import cursor

router = APIRouter()


class Service(BaseModel):
    ip: str
    port: int
    transport: str
    product: str | None
    version: str | None
    hostname: str | None
    country_code: str | None
    route: str
    confidence: str
    evidence_text: str | None
    first_seen: datetime
    last_seen: datetime


class Finding(BaseModel):
    finding_type: str
    kind: str
    salesperson_line: str | None
    exploitation_final: str | None
    severity: int | None
    likelihood: int | None
    score: int | None
    cve_summary: str | None
    services: list[Service]


class CompanyPage(CompanyRow):
    scorer: str
    file_id: str
    visible_services: int
    countries: list[str]
    findings: list[Finding]


class FindingType(BaseModel):
    finding_type: str
    kind: str
    answer_status: str | None
    exploitation_final: str | None
    automatable: str | None
    technical_impact: str | None
    salesperson_line: str | None
    severity: int | None
    likelihood: int | None
    score: int | None
    companies: int


@router.get("/companies/{company_key}")
def company_page(
    company_key: str,
    request: Request,
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
    scorer: str | None = None,
) -> CompanyPage:
    chosen = chosen_scorer(request, scorer)
    found = matching(cur, Filters(), chosen, company_key).fetchall()
    if not found:
        raise HTTPException(status_code=404, detail=f"no company {company_key} under {chosen}")
    (visible,) = cur.execute(
        "SELECT visible_services FROM company WHERE company_scorer = ? AND company_key = ?",
        [chosen, company_key],
    ).fetchall()[0]
    rows = cur.execute(
        """
        SELECT finding_type, kind, salesperson_line, exploitation_final, severity, likelihood,
          score, cve_summary, ip, port, transport, product, version, hostname, country_code,
          route, confidence, evidence_text, first_seen, last_seen
        FROM company_finding WHERE company_key = ?
        ORDER BY score DESC NULLS LAST, finding_type,
          CASE confidence WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, ip, port
        """,
        [company_key],
    ).fetchall()
    finding_fields = [f for f in Finding.model_fields if f != "services"]
    findings = []
    for _, grouped in groupby(rows, key=lambda r: r[0]):
        group = list(grouped)
        findings.append(
            Finding(
                **dict(zip(finding_fields, group[0][:8], strict=True)),
                services=[
                    Service(**dict(zip(Service.model_fields, r[8:], strict=True))) for r in group
                ],
            )
        )
    return CompanyPage(
        **as_row(found[0]).model_dump(),
        scorer=chosen,
        file_id=request.app.state.scan.file_id,
        visible_services=visible,
        countries=sorted({r[14] for r in rows if r[14]}),
        findings=findings,
    )


@router.get("/finding-types")
def finding_types(
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> list[FindingType]:
    """The filter's choices: only types found on at least one company, since any other type
    would filter down to an empty list."""
    rows = cur.execute(
        """
        SELECT finding_type, any_value(kind), any_value(answer_status),
          any_value(exploitation_final), any_value(automatable), any_value(technical_impact),
          any_value(salesperson_line), any_value(severity), any_value(likelihood),
          any_value(score), count(DISTINCT company_key)
        FROM company_finding GROUP BY finding_type
        ORDER BY any_value(score) DESC NULLS LAST, finding_type
        """
    ).fetchall()
    return [FindingType(**dict(zip(FindingType.model_fields, r, strict=True))) for r in rows]
