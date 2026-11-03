"""Step 1a. Every banner column: records where it is set, and distinct IPs.

Lists count as set only when non-empty. Distinct IPs are exact on the sample and
HyperLogLog estimates (approx_count_distinct) on the full file.
Run: uv run python archive/blind-analysis/scripts/01_census_columns.py sample|full
"""

from _db import connect

con, ds = connect()
cols = con.execute("DESCRIBE SELECT * FROM banner").fetchall()
skip = {"parse_error", "parse_error_excerpt", "file_id", "ip", "rec_id"}
agg = "count(DISTINCT ip)" if ds == "sample" else "approx_count_distinct(ip)"

total, ips = con.execute(f"SELECT count(*), {agg} FROM banner").fetchone()  # type: ignore[misc]
print(f"dataset={ds} records={total} distinct_ips={ips}")

exprs = []
for name, typ, *_ in cols:
    if name in skip:
        continue
    cond = f'len("{name}") > 0' if typ.endswith("[]") else f'"{name}" IS NOT NULL'
    if typ.startswith("MAP"):
        cond = f'"{name}" IS NOT NULL AND cardinality("{name}") > 0'
    exprs.append((name, cond))

results = []
batch = 40
for i in range(0, len(exprs), batch):
    chunk = exprs[i : i + batch]
    sel = ", ".join(f"count(*) FILTER (WHERE {c}), {agg} FILTER (WHERE {c})" for _, c in chunk)
    row = con.execute(f"SELECT {sel} FROM banner").fetchone()
    assert row is not None
    for j, (name, _) in enumerate(chunk):
        results.append((name, row[2 * j], row[2 * j + 1]))

results.sort(key=lambda r: -r[1])
print("column | records | share | distinct_ips")
for name, n, d in results:
    print(f"{name} | {n} | {n / total:.4%} | {d}")
