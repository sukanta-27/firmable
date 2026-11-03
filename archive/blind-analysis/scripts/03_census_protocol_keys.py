"""Step 1c. Keys inside every protocol object (one level deep), with records and IPs.

Only scalar-valued keys also get their top values, so booleans like
`mongodb.authentication` or `vnc.security_types` show what the scanner actually saw.
Run: uv run python archive/blind-analysis/scripts/03_census_protocol_keys.py sample|full
"""

from _db import connect

con, ds = connect()
print(f"dataset={ds}")
PROTOCOLS = [
    r[0]
    for r in con.execute("SELECT DISTINCT unnest(proto_keys) FROM banner ORDER BY 1").fetchall()
]
print("protocol | key | records | ips | top values (scalar keys, up to 6)")
for p in PROTOCOLS:
    rows = con.execute(
        f"""WITH kv AS (
              SELECT ip, unnest(map_entries(json_transform("{p}", '"MAP(VARCHAR, JSON)"'))) AS e
              FROM banner WHERE "{p}" IS NOT NULL AND json_type("{p}") = 'OBJECT'),
            flat AS (SELECT ip, e.key AS k, e.value AS v FROM kv),
            keys AS (SELECT k, count(*) AS n, count(DISTINCT ip) AS ips FROM flat GROUP BY k),
            vals AS (
              SELECT k, left(CAST(v AS VARCHAR), 60) AS val, count(*) AS c FROM flat
              WHERE json_type(v) NOT IN ('OBJECT', 'ARRAY') GROUP BY k, val
              QUALIFY row_number() OVER (PARTITION BY k ORDER BY c DESC, val) <= 6)
            SELECT k, n, ips, string_agg(val || '=' || c, '; ' ORDER BY c DESC, val),
                   count(*) OVER () AS n_keys
            FROM keys LEFT JOIN vals USING (k) GROUP BY k, n, ips ORDER BY n DESC, k"""
    ).fetchall()
    # `mac` (and any object keyed by data rather than schema) has one key per value.
    cap = 5 if rows and rows[0][4] > 300 else 80
    for k, n, ips, tops, _ in rows[:cap]:
        print(f"{p} | {k} | {n} | {ips} | {tops or ''}")
    if len(rows) > cap:
        print(f"{p} | <{len(rows) - cap} more keys of {rows[0][4]}> | | | ")
    non_obj = con.execute(
        f"""SELECT json_type("{p}") AS t, count(*) FROM banner
            WHERE "{p}" IS NOT NULL AND json_type("{p}") <> 'OBJECT' GROUP BY 1"""
    ).fetchall()
    for t, n in non_obj:
        print(f"{p} | <{t}> | {n} | | ")
