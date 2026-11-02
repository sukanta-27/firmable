"""The salesperson's app: reads the one published scan and serves it to logged-in users.

Run with `uv run uvicorn api.main:create_app --factory`; a factory, so tests build the app
with their own settings instead of whatever the environment holds at import time.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import duckdb
from fastapi import APIRouter, Depends, FastAPI, Request, Response
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from api import auth
from api.settings import ApiSettings

PUBLISHED_TABLES = ("company", "company_finding")


class Health(BaseModel):
    status: str


def open_published(settings: ApiSettings) -> duckdb.DuckDBPyConnection:
    root = settings.publish_root
    if not (root / "publish.json").exists():
        raise RuntimeError(f"no published scan in {root}; run `pipeline publish` first")
    con = duckdb.connect()
    for table in PUBLISHED_TABLES:
        con.execute(f"CREATE VIEW {table} AS SELECT * FROM read_parquet('{root / table}.parquet')")
    scorers = {s for (s,) in con.execute("SELECT DISTINCT company_scorer FROM company").fetchall()}
    if settings.company_scorer not in scorers:
        raise RuntimeError(f"COMPANY_SCORER {settings.company_scorer} not in {sorted(scorers)}")
    return con


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    settings = settings or ApiSettings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.con = open_published(settings)
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
    app.include_router(protected)
    return app
