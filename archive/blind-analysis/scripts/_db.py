"""Shared DuckDB connection for the blind-analysis scripts.

Usage from a script: `con, ds = connect()` reads the dataset name (sample | full) from
argv[1]. Views: banner (parse_error IS NULL only), vuln, cve_text. Read-only.
"""

import sys
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[3]


def connect() -> tuple[duckdb.DuckDBPyConnection, str]:
    ds = sys.argv[1] if len(sys.argv) > 1 else "sample"
    assert ds in ("sample", "full"), ds
    base = ROOT / "data" / "runs" / ds / "bronze"
    con = duckdb.connect()
    con.execute("SET threads = 8")
    con.execute("SET memory_limit = '14GB'")
    con.execute("SET preserve_insertion_order = false")
    con.execute(
        f"CREATE VIEW banner AS SELECT * FROM read_parquet('{base}/banner/*/*.parquet') "
        "WHERE parse_error IS NULL"
    )
    for t in ("vuln", "cve_text"):
        con.execute(f"CREATE VIEW {t} AS SELECT * FROM read_parquet('{base}/{t}/*/*.parquet')")
    return con, ds


def show(con: duckdb.DuckDBPyConnection, sql: str, title: str = "", width: int = 160) -> None:
    if title:
        print(f"\n## {title}")
    rel = con.sql(sql)
    cols = rel.columns
    rows = rel.fetchall()
    print(" | ".join(cols))
    for r in rows:
        print(" | ".join(_fmt(v, width) for v in r))


def _fmt(v: object, width: int) -> str:
    s = "NULL" if v is None else str(v)
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= width else s[: width - 3] + "..."
