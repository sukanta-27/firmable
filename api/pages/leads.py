import math
from typing import Annotated
from urllib.parse import urlencode

import duckdb
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from api import company
from api.companies import BREACH_TYPES, Filters, Page, list_companies, matching
from api.company import FindingType
from api.db import cursor
from api.pages.common import page_context, page_user, templates
from api.settings import ApiSettings

router = APIRouter()

PAGE_SIZE = 50
SCORERS = {
    "worst_x_confidence_v1": ("Worst single problem", "The usual list"),
    "sum_x_confidence_v1": ("Problems add up", "Big organisations rise"),
}
QUICK_VIEWS = [
    (
        "The worst ones we're sure about",
        "confidence=High&could_give_full_control=true&attacked_in_the_wild=true",
    ),
    ("Open databases", "finding_type=tag_database"),
    ("Windows remote login open", "finding_type=rdp_exposed"),
    ("Signs of a break-in", "already_breached=true"),
]
FLAG_LABELS = {
    "could_give_full_control": "Would give an attacker full control",
    "attacked_in_the_wild": "Attackers use this kind of hole",
    "already_breached": "Signs of a break-in",
}


class FilterCounts(BaseModel):
    """Scan-wide counts beside each filter; they don't follow the other filters."""

    high: int
    could_give_full_control: int
    attacked_in_the_wild: int
    already_breached: int
    ranked: int


class Chip(BaseModel):
    label: str
    href: str


def problem_label(t: FindingType) -> str:
    """A short name for a finding type until the AI pass writes one: the plain line up to its
    first clause break."""
    if not t.salesperson_line:
        return t.finding_type
    cut = min(
        (i for i in (t.salesperson_line.find(";"), t.salesperson_line.find(",")) if i > 0),
        default=len(t.salesperson_line),
    )
    return t.salesperson_line[:cut].rstrip(".")


def filter_counts(cur: duckdb.DuckDBPyConnection, scorer: str) -> FilterCounts:
    def count(filters: Filters) -> int:
        (n,) = matching(cur, filters, scorer).count("*").fetchall()[0]
        return int(n)

    (ranked,) = matching(cur, Filters(), scorer).filter("rank IS NOT NULL").count("*").fetchall()[0]
    return FilterCounts(
        high=count(Filters(confidence=["High"])),
        could_give_full_control=count(Filters(could_give_full_control=True)),
        attacked_in_the_wild=count(Filters(attacked_in_the_wild=True)),
        already_breached=count(Filters(already_breached=True)),
        ranked=int(ranked),
    )


def query_items(request: Request) -> list[tuple[str, str]]:
    """The list's own parameters, in the order given, without paging."""
    return [(k, v) for k, v in request.query_params.multi_items() if k not in ("offset", "limit")]


def chips(items: list[tuple[str, str]], types: dict[str, FindingType]) -> list[Chip]:
    out = []
    for i, (key, value) in enumerate(items):
        if key == "q" and value:
            label = f'Search: "{value}"'
        elif key == "confidence":
            label = "High confidence only" if value == "High" else f"Confidence: {value}"
        elif key in FLAG_LABELS and value == "true":
            label = FLAG_LABELS[key]
        elif key == "finding_type":
            t = types.get(value)
            label = f"Problem: {problem_label(t) if t else value}"
        else:
            continue
        out.append(Chip(label=label, href="/?" + urlencode(items[:i] + items[i + 1 :])))
    return out


def pager(total: int, offset: int) -> list[int | None]:
    """Page numbers to show: the first, the last and two either side of the current one, with
    None where pages are skipped."""
    pages = math.ceil(total / PAGE_SIZE)
    current = offset // PAGE_SIZE + 1
    shown = sorted({1, pages, *range(max(1, current - 2), min(pages, current + 2) + 1)})
    out: list[int | None] = []
    for n in shown:
        if out and n - (out[-1] or 0) > 1:
            out.append(None)
        out.append(n)
    return out


@router.get("/", response_class=HTMLResponse)
def leads(
    request: Request,
    page: Annotated[Page, Query()],
    user: Annotated[str, Depends(page_user)],
    cur: Annotated[duckdb.DuckDBPyConnection, Depends(cursor)],
) -> Response:
    page = page.model_copy(update={"limit": PAGE_SIZE})
    result = list_companies(request, page, cur)
    types = {t.finding_type: t for t in company.finding_types(cur)}
    items = query_items(request)
    chip_list = chips(items, types)
    context: dict[str, object] = {
        "result": result,
        "page": page,
        "types": types,
        "chips": chip_list,
        "remove_last": chip_list[-1].href if chip_list else None,
        "query": urlencode(items),
        "list_query": request.url.query,
        "pages": pager(result.total, page.offset),
        "current_page": page.offset // PAGE_SIZE + 1,
        "page_size": PAGE_SIZE,
        "scorers": SCORERS,
        "breach_types": BREACH_TYPES,
    }
    if request.headers.get("hx-request"):
        return templates.TemplateResponse(request, "_results.html", context)
    settings: ApiSettings = request.app.state.settings
    by_reach = sorted(types.values(), key=lambda t: -t.companies)
    shortlist = by_reach[:5] + [t for t in by_reach[5:] if t.finding_type in page.finding_type]
    context |= {
        **page_context(request, user),
        "active": "leads",
        "counts": filter_counts(cur, settings.company_scorer),
        "quick_views": QUICK_VIEWS,
        "shortlist": shortlist,
        "problem_label": problem_label,
    }
    return templates.TemplateResponse(request, "leads.html", context)
