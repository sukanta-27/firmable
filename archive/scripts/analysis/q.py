"""Run SQL against the flattened Parquet tables and print each result as a text table.

Usage: q.py (FILE.sql | "SQL text") [--flat DIR] [--rows N]
Views available to the SQL: banners, vulns.
"""
import argparse
import os
import sys

import duckdb

MAXW = 70


def fmt(v):
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.4g}" if abs(v) < 1e-2 or abs(v) >= 1e6 else f"{v:.2f}"
    s = str(v).replace("\n", "\\n")
    return s if len(s) <= MAXW else s[: MAXW - 1] + "…"


def show(rel, rows):
    cols = rel.columns
    data = rel.limit(rows + 1).fetchall()
    more = len(data) > rows
    data = [[fmt(v) for v in r] for r in data[:rows]]
    widths = [max(len(c), *(len(r[i]) for r in data)) if data else len(c) for i, c in enumerate(cols)]
    line = lambda r: "| " + " | ".join(x.ljust(w) for x, w in zip(r, widths)) + " |"
    print(line(cols))
    print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for r in data:
        print(line(r))
    if more:
        print(f"... (more than {rows} rows)")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sql")
    ap.add_argument("--flat", default="archive/data/flat/main")
    ap.add_argument("--rows", type=int, default=60)
    ap.add_argument("--csv", help="also write the last statement's full result to this CSV path")
    a = ap.parse_args()
    con = duckdb.connect()
    con.execute("SET threads=12")
    con.execute("SET memory_limit='16GB'")
    con.execute(f"CREATE VIEW banners AS SELECT * FROM read_parquet('{a.flat}/banners.parquet')")
    con.execute(f"CREATE VIEW vulns AS SELECT * FROM read_parquet('{a.flat}/vulns.parquet')")
    views = os.path.join(os.path.dirname(os.path.abspath(__file__)), "views.sql")
    if os.path.exists(views):
        con.execute(open(views).read())
    text = open(a.sql).read() if os.path.exists(a.sql) else a.sql
    stmts = [s.strip() for s in text.split(";") if s.strip()]
    for i, stmt in enumerate(stmts):
        title = stmt.splitlines()[0] if stmt.startswith("--") else None
        if title:
            print(f"### {title.lstrip('- ')}")
        rel = con.sql(stmt)
        if rel is not None:
            show(rel, a.rows)
            if a.csv and i == len(stmts) - 1:
                rel.write_csv(a.csv)
                print(f"(written to {a.csv})")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
