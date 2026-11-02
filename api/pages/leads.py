from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from api.pages.common import page_context, page_user, templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def leads(request: Request, user: Annotated[str, Depends(page_user)]) -> Response:
    return templates.TemplateResponse(
        request, "leads.html", {**page_context(request, user), "active": "leads"}
    )
