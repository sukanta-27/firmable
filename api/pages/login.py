from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from api.auth import attempt_login
from api.pages.common import safe_next, templates

router = APIRouter()

MESSAGES = {
    "wrong": "That username and password don't match. Check both and try again.",
    "throttled": "Too many attempts. Try again in a few minutes.",
    "expired": "You were logged out. Log in to go back to where you were.",
}


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", reason: str | None = None) -> Response:
    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": safe_next(next), "message": MESSAGES.get(reason or ""), "username": ""},
    )


@router.post("/login", response_class=HTMLResponse)
def login_form(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    outcome = attempt_login(request, username, password)
    if outcome == "ok":
        return RedirectResponse(safe_next(next), status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": safe_next(next), "message": MESSAGES[outcome], "username": username},
        status_code=429 if outcome == "throttled" else 401,
    )


@router.post("/logout")
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
