"""The salesperson's app: reads the one published scan and serves it to logged-in users.

Run with `uv run uvicorn api.main:create_app --factory`; a factory, so tests build the app
with their own settings instead of whatever the environment holds at import time.
"""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import duckdb
from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from api import auth, companies, company, how_we_know, scan
from api.pages import company as company_pages
from api.pages import leads, login
from api.pages.common import LoginRequired, login_url, templates
from api.settings import ApiSettings

PUBLISHED_TABLES = ("company", "company_finding")


class Health(BaseModel):
    status: str


class Scan(BaseModel):
    """What the app was started on, read once from the published folder."""

    file_id: str
    received_at: datetime
    scorers: list[str]


def open_published(settings: ApiSettings) -> tuple[duckdb.DuckDBPyConnection, Scan]:
    root = settings.publish_root
    if not (root / "publish.json").exists():
        raise RuntimeError(f"no published scan in {root}; run `pipeline publish` first")
    manifest = json.loads((root / "manifest.json").read_text())
    con = duckdb.connect()
    for table in PUBLISHED_TABLES:
        con.execute(f"CREATE VIEW {table} AS SELECT * FROM read_parquet('{root / table}.parquet')")
    rows = con.execute("SELECT DISTINCT company_scorer FROM company ORDER BY 1").fetchall()
    scorers = [s for (s,) in rows]
    if settings.company_scorer not in scorers:
        raise RuntimeError(f"COMPANY_SCORER {settings.company_scorer} not in {scorers}")
    scan = Scan(file_id=manifest["file_id"], received_at=manifest["received_at"], scorers=scorers)
    return con, scan


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    settings = settings or ApiSettings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.con, app.state.scan = open_published(settings)
        try:
            yield
        finally:
            app.state.con.close()

    app = FastAPI(title="Exposure leads", lifespan=lifespan)
    app.state.settings = settings
    app.state.throttle = auth.Throttle()
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret.get_secret_value(),
        max_age=settings.session_hours * 3600,
        same_site="lax",
        https_only=settings.cookie_secure,
    )

    @app.middleware("http")
    async def noindex(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # The app shows IP, port and exploit evidence for real, vulnerable services.
        response = await call_next(request)
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response

    @app.get("/api/health")
    def health() -> Health:
        return Health(status="ok")

    app.include_router(auth.router)
    protected = APIRouter(prefix="/api", dependencies=[Depends(auth.current_user)])
    protected.include_router(auth.me_router)
    protected.include_router(companies.router)
    protected.include_router(company.router)
    protected.include_router(scan.router)
    protected.include_router(how_we_know.router)
    app.include_router(protected)

    app.include_router(login.router)
    app.include_router(leads.router)
    app.include_router(company_pages.router)

    @app.exception_handler(LoginRequired)
    def to_login(request: Request, _: LoginRequired) -> Response:
        target = login_url(request)
        if request.headers.get("hx-request"):
            # A 200, so htmx acts on the header whatever its error settings; a redirect
            # would be followed inside the swap and draw the login form in the results.
            return Response(status_code=200, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=303)

    @app.exception_handler(500)
    def server_error(request: Request, _: Exception) -> Response:
        if request.url.path.startswith("/api"):
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        return templates.TemplateResponse(
            request, "error.html", {"full": not request.headers.get("hx-request")}, 500
        )

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), "static")
    return app
