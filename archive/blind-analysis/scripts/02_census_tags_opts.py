"""Step 1b. Census of tags, opts keys, opts.vulns, opts.heartbleed outcome, extra keys,
probes, ports, products, and vuln.extra keys.

Distinct IPs are exact on both datasets here (one aggregate per query).
Run: uv run python archive/blind-analysis/scripts/02_census_tags_opts.py sample|full
"""

from _db import connect, show

con, ds = connect()
print(f"dataset={ds}")

show(
    con,
    """SELECT t AS tag, count(*) AS records, count(DISTINCT ip) AS ips
       FROM (SELECT unnest(tags) AS t, ip FROM banner) GROUP BY t ORDER BY records DESC""",
    "tags",
)
show(
    con,
    """SELECT k AS opts_key, count(*) AS records, count(DISTINCT ip) AS ips
       FROM (SELECT unnest(json_keys(opts)) AS k, ip FROM banner)
       GROUP BY k ORDER BY records DESC""",
    "opts keys",
)
show(
    con,
    """SELECT json_array_length(json_extract(opts, '$.vulns')) AS n_tested_vulns,
              count(*) AS records
       FROM banner WHERE json_extract(opts, '$.vulns') IS NOT NULL GROUP BY 1 ORDER BY 1""",
    "opts.vulns list length",
)
show(
    con,
    """SELECT v AS opts_vuln, count(*) AS records, count(DISTINCT ip) AS ips
       FROM (SELECT unnest(json_extract_string(opts, '$.vulns[*]')) AS v, ip FROM banner
             WHERE json_extract(opts, '$.vulns') IS NOT NULL)
       GROUP BY v ORDER BY records DESC""",
    "opts.vulns entries",
)
show(
    con,
    r"""SELECT regexp_extract(json_extract_string(opts, '$.heartbleed'),
                          ' - ([A-Z]+)', 1) AS outcome,
              count(*) AS records, count(DISTINCT ip) AS ips
       FROM banner WHERE json_extract(opts, '$.heartbleed') IS NOT NULL
       GROUP BY 1 ORDER BY records DESC""",
    "opts.heartbleed outcome",
)
show(
    con,
    """SELECT k AS extra_key, count(*) AS records
       FROM (SELECT unnest(map_keys(extra)) AS k FROM banner WHERE extra IS NOT NULL)
       GROUP BY k ORDER BY records DESC""",
    "banner.extra keys",
)
show(
    con,
    """SELECT k AS vuln_extra_key, count(*) AS entries
       FROM (SELECT unnest(map_keys(extra)) AS k FROM vuln WHERE extra IS NOT NULL)
       GROUP BY k ORDER BY entries DESC""",
    "vuln.extra keys",
)
show(
    con,
    """SELECT transport, ip_version, count(*) AS records
       FROM banner GROUP BY ALL ORDER BY records DESC""",
    "transport x ip_version",
)
show(
    con,
    """SELECT probe, count(*) AS records, count(DISTINCT ip) AS ips
       FROM banner GROUP BY probe ORDER BY records DESC""",
    "probes (all)",
)
show(
    con,
    """SELECT port, count(*) AS records FROM banner GROUP BY port ORDER BY records DESC LIMIT 60""",
    "top 60 ports",
)
show(
    con,
    """SELECT product, count(*) AS records, count(DISTINCT ip) AS ips
       FROM banner WHERE product IS NOT NULL GROUP BY product ORDER BY records DESC LIMIT 150""",
    "top 150 products",
)
show(
    con,
    """SELECT scanner_region, count(*) AS records FROM banner GROUP BY 1 ORDER BY 2 DESC""",
    "scanner regions",
)
show(
    con,
    """SELECT min(ts) AS first_seen, max(ts) AS last_seen FROM banner""",
    "scan window",
)
