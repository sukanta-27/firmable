from collections.abc import Iterator

import duckdb
from fastapi import Request


def cursor(request: Request) -> Iterator[duckdb.DuckDBPyConnection]:
    """A cursor of the app's one connection: a connection isn't safe to share across the
    threads FastAPI runs `def` routes on, a cursor per request is."""
    cur: duckdb.DuckDBPyConnection = request.app.state.con.cursor()
    try:
        yield cur
    finally:
        cur.close()
