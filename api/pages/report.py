from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from api import how_we_know
from api.pages.common import page_context, page_user, templates

router = APIRouter()

QUESTIONS = {
    "exploitation": "Are criminals using this kind of hole?",
    "automatable": "Can an attacker automate it?",
    "technical_impact": "What would an attacker get?",
}


def model_name(model_id: str) -> str:
    """`claude-opus-5-5` → `Opus`: the family is what a reader compares."""
    parts = model_id.split("-")
    return parts[1].title() if len(parts) > 1 else model_id


def case_name(case: str) -> str:
    return case.replace("_", " ").capitalize()


@router.get("/how-we-know", response_class=HTMLResponse)
def how_we_know_page(request: Request, user: Annotated[str, Depends(page_user)]) -> Response:
    return templates.TemplateResponse(
        request,
        "how_we_know.html",
        {
            **page_context(request, user),
            "active": "how",
            "r": how_we_know.how_we_know(request),
            "questions": QUESTIONS,
            "model_name": model_name,
            "case_name": case_name,
        },
    )
