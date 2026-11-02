import math
from collections import Counter
from typing import Annotated
from urllib.parse import urlencode

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from api import company
from api.company import CompanyPage, Finding
from api.db import cursor
from api.pages.common import BREAK_IN_TYPES, badge, page_context, page_user, templates
from api.pages.leads import PAGE_SIZE, SCORERS, chips, problem_label, ranked_total
from api.settings import ApiSettings

router = APIRouter()

SERVICES_SHOWN = 5
SERVICES_PAGE = 25
FINDINGS_SHOWN = 6


def back_link(request: Request, types: dict[str, company.FindingType]) -> tuple[str, str]:
    """Where "Back to leads" goes, and what it says: the list the person came from."""
    carried = [(k, v) for k, v in request.query_params.multi_items() if k != "services_from"]
    if not carried:
        return "/", "All leads"
    filters = len(chips([(k, v) for k, v in carried if k != "offset"], types))
    page = int(request.query_params.get("offset", 0)) // PAGE_SIZE + 1
    parts = [f"{filters} filter{'s' if filters != 1 else ''}"] if filters else []
    parts += [f"page {page}"] if page > 1 else []
    label = "Back to leads" + (f" ({' · '.join(parts)})" if parts else "")
    return "/?" + urlencode(carried), label


def summary(f: Finding) -> dict[str, list[tuple[str, int]]]:
    """For a finding with many services: how sure, what software, where, without reading
    every row."""
    return {
        "tied": Counter(badge(s.confidence, s.route)[0] for s in f.services).most_common(),
        "software": Counter(s.product or "not identified" for s in f.services).most_common(3),
        "countries": Counter(s.country_code or "unknown" for s in f.services).most_common(3),
    }


def load(
    request: Request, cur: duckdb.DuckDBPyConnection, company_key: str
) -> tuple[CompanyPage | None, str]:
    settings: ApiSettings = request.app.state.settings
    scorer = request.query_params.get("scorer") or settings.company_scorer
    try:
        return company.company_page(company_key, request, cur, scorer), scorer
    except HTTPException as e:
        if e.status_code == 404:
            return None, scorer
        raise


def not_found(request: Request, user: str, company_key: str) -> Response:
    return templates.TemplateResponse(
        request,
        "not_found.html",
        {**page_context(request, user), "key": company_key, "q": urlencode({"q": company_key})},
        status_code=404,
    )


@router.get("/companies/{company_key}", response_class=HTMLResponse)
def company_view(
    company_key: str,
    request: Request,
    user: Annotated[str, Depends(page_user)],
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> Response:
    c, scorer = load(request, cur, company_key)
    if c is None:
        return not_found(request, user, company_key)
    types = {t.finding_type: t for t in company.finding_types(cur)}
    back_href, back_label = back_link(request, types)
    shown, folded = c.findings[:FINDINGS_SHOWN], c.findings[FINDINGS_SHOWN:]
    if len(c.findings) == FINDINGS_SHOWN + 1:
        shown, folded = c.findings, []
    return templates.TemplateResponse(
        request,
        "company.html",
        {
            **page_context(request, user),
            "active": "leads",
            "c": c,
            "rule": SCORERS[scorer][0],
            "ranked": ranked_total(cur, scorer),
            "back_href": back_href,
            "back_label": back_label,
            "carried": request.url.query,
            "shown": shown,
            "folded": folded,
            "services_shown": SERVICES_SHOWN,
            "summary": summary,
            "single": len(c.findings) == 1 and len(c.findings[0].services) == 1,
            "breach_types": BREAK_IN_TYPES,
            "problem_label": problem_label,
            "types": types,
        },
    )


@router.get("/companies/{company_key}/findings/{finding_type}", response_class=HTMLResponse)
def services_view(
    company_key: str,
    finding_type: str,
    request: Request,
    user: Annotated[str, Depends(page_user)],
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> Response:
    c, _ = load(request, cur, company_key)
    finding = next((f for f in c.findings if f.finding_type == finding_type), None) if c else None
    if c is None or finding is None:
        return not_found(request, user, company_key)
    # The list's own offset rides along for the way back, so this page pages with its own.
    start = max(0, int(request.query_params.get("services_from", 0)))
    carried = [(k, v) for k, v in request.query_params.multi_items() if k != "services_from"]
    pages = math.ceil(len(finding.services) / SERVICES_PAGE)
    return templates.TemplateResponse(
        request,
        "services.html",
        {
            **page_context(request, user),
            "active": "leads",
            "c": c,
            "f": finding,
            "rows": finding.services[start : start + SERVICES_PAGE],
            "start": start,
            "page_size": SERVICES_PAGE,
            "pages": pages,
            "current": start // SERVICES_PAGE + 1,
            "carried": urlencode(carried),
            "summary": summary(finding),
            "problem_label": problem_label,
            "types": {t.finding_type: t for t in company.finding_types(cur)},
        },
    )
