"""Claims under test: each row of the CLAUDE.md trap table, re-measured from bronze.
(The CVE and kev rows are measured in 05_vuln_fields.py.)
Run: uv run python archive/blind-analysis/scripts/06_claims.py sample|full
"""

from _db import ROOT, connect, show

con, ds = connect()
stats = ROOT / "archive" / "blind-analysis" / "cache" / f"ip_stats.{ds}.parquet"
print(f"dataset={ds}")

# CDN rows
show(
    con,
    """SELECT count(*) AS cdn_records, count(DISTINCT ip) AS cdn_ips,
      round(100.0 * count(*) / (SELECT count(*) FROM banner), 1) AS pct_of_all_records,
      count(*) FILTER (WHERE cves IS NOT NULL AND len(cves) > 0) AS cdn_with_cves,
      count(*) FILTER (WHERE list_contains(tags, 'eol-product')) AS cdn_eol_product
    FROM banner WHERE list_contains(tags, 'cdn')""",
    "C1. cdn-tagged records",
)
show(
    con,
    """SELECT org, count(*) AS records FROM banner WHERE list_contains(tags, 'cdn')
    GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    "C2. cdn-tagged records by org",
)
show(
    con,
    """SELECT coalesce(http_server, product, '<none>') AS server, count(*) AS records
    FROM banner WHERE list_contains(tags, 'cdn') GROUP BY 1 ORDER BY 2 DESC LIMIT 12""",
    "C3. cdn-tagged records by HTTP Server header (or product)",
)
show(
    con,
    """SELECT port, count(*) AS records, count(DISTINCT ip) AS ips
    FROM banner WHERE list_contains(tags, 'cdn') GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    "C4. cdn-tagged records by port",
)
show(
    con,
    """SELECT p.product, count(*) AS records FROM banner p
    WHERE list_contains(tags, 'cdn') AND cves IS NOT NULL AND len(cves) > 0
    GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    "C5. products on cdn-tagged records that carry CVEs",
)
show(
    con,
    """SELECT http_title, count(*) AS records FROM banner WHERE list_contains(tags, 'cdn')
    GROUP BY 1 ORDER BY 2 DESC LIMIT 12""",
    "C6. cdn-tagged records by HTTP title",
)
# Honeypots
show(
    con,
    f"""SELECT count(*) AS hp_records, count(DISTINCT b.ip) AS hp_ips,
      quantile_cont(s.ip_ports, [0.1, 0.5, 0.9]) AS ports_per_hp_ip_q,
      count(*) FILTER (WHERE cves IS NOT NULL AND len(cves) > 0) AS hp_with_cves,
      count(*) FILTER (WHERE rec_id IN (SELECT rec_id FROM vuln WHERE verified))
        AS hp_with_verified_cve
    FROM banner b JOIN '{stats}' s USING (ip) WHERE list_contains(tags, 'honeypot')""",
    "H1. honeypot-tagged records and their IPs' port counts",
)
show(
    con,
    f"""SELECT ip_ports >= 20 AS ip_20plus_ports, ip_honeypot, count(*) AS ips,
      sum(ip_records) AS records
    FROM '{stats}' GROUP BY ALL ORDER BY ALL""",
    "H2. IPs by honeypot tag and >=20 ports",
)
show(
    con,
    f"""WITH s AS (SELECT * FROM '{stats}' WHERE ip_ports >= 20 AND NOT ip_honeypot),
    b AS (SELECT ip, count(DISTINCT product) AS products,
                 count(DISTINCT md5(left(data, 200))) AS distinct_replies,
                 count(*) AS recs
          FROM banner WHERE ip IN (SELECT ip FROM s) GROUP BY ip)
    SELECT count(*) AS ips,
      quantile_cont(products, [0.5, 0.9]) AS products_per_ip_q,
      list_transform(quantile_cont(distinct_replies::DOUBLE / recs, [0.1, 0.5, 0.9]),
        lambda x: round(x, 3))
        AS distinct_reply_ratio_q,
      count(*) FILTER (WHERE products >= 10) AS ips_10plus_products
    FROM b""",
    "H3. untagged IPs with >=20 ports: how varied are their replies?",
)
show(
    con,
    f"""WITH s AS (SELECT ip FROM '{stats}' WHERE ip_ports >= 20 AND NOT ip_honeypot)
    SELECT org, count(DISTINCT ip) AS ips, count(*) AS records
    FROM banner WHERE ip IN (SELECT ip FROM s) GROUP BY 1 ORDER BY 2 DESC LIMIT 10""",
    "H4. untagged IPs with >=20 ports, by org",
)
show(
    con,
    f"""WITH s AS (SELECT ip FROM '{stats}' WHERE ip_ports >= 20 AND NOT ip_honeypot)
    SELECT list_contains(tags, 'cdn') AS cdn, count(*) AS records, count(DISTINCT ip) AS ips
    FROM banner WHERE ip IN (SELECT ip FROM s) GROUP BY 1""",
    "H5. untagged IPs with >=20 ports: share carrying the cdn tag",
)
# Probe vs service
show(
    con,
    """SELECT probe, count(*) AS records,
      round(100.0 * count(*) FILTER (WHERE product IS NULL) / count(*), 1) AS pct_no_product,
      round(100.0 * count(*) FILTER (WHERE data_len = 0 OR data IS NULL) / count(*), 1)
        AS pct_empty_reply,
      round(100.0 * count(*) FILTER (WHERE http_status IS NOT NULL) / count(*), 1) AS pct_http,
      any_value(product) FILTER (WHERE product IS NOT NULL) AS example_product
    FROM banner GROUP BY probe HAVING count(*) >= 4000 ORDER BY records DESC LIMIT 60""",
    "P1. probe name vs what came back",
)
show(
    con,
    """SELECT probe, product, count(*) AS records FROM banner
    WHERE probe IN ('http', 'https', 'ssh', 'telnet', 'rdp', 'ftp', 'mysql', 'redis', 'smb')
      AND product IS NOT NULL
    GROUP BY probe, product
    QUALIFY row_number() OVER (PARTITION BY probe ORDER BY records DESC) <= 4
    ORDER BY probe, records DESC""",
    "P2. products seen under common protocol probes",
)
# telnet object placement
show(
    con,
    """SELECT port, coalesce(product, '<none>') AS product,
      regexp_matches(lower(data), 'login|user ?name|password') AS login_prompt,
      count(*) AS records
    FROM banner WHERE telnet IS NOT NULL GROUP BY ALL ORDER BY records DESC LIMIT 15""",
    "T1. telnet object: ports, products, login prompt",
)
show(
    con,
    """SELECT count(*) AS telnet_records,
      count(*) FILTER (WHERE port IN (23, 2323)) AS on_23_2323,
      count(*) FILTER (WHERE port NOT IN (23, 2323)
                       AND regexp_matches(lower(data), 'login|user ?name|password'))
        AS other_port_with_prompt,
      count(*) FILTER (WHERE ssh_type IS NOT NULL OR vnc IS NOT NULL OR data LIKE 'SSH-%'
                       OR data LIKE 'RFB %') AS with_ssh_or_vnc
    FROM banner WHERE telnet IS NOT NULL""",
    "T2. telnet object on SSH/VNC banners?",
)
# org / isp
show(
    con,
    """WITH o AS (SELECT org, count(DISTINCT ip) AS org_ips FROM banner GROUP BY org)
    SELECT count(*) AS records,
      round(100.0 * count(*) FILTER (WHERE b.org = b.isp) / count(*), 1) AS pct_org_eq_isp,
      round(100.0 * count(*) FILTER (WHERE o.org_ips >= 1000) / count(*), 1)
        AS pct_org_has_1000plus_ips,
      round(100.0 * count(*) FILTER (WHERE o.org_ips >= 10000) / count(*), 1)
        AS pct_org_has_10000plus_ips,
      round(100.0 * count(*) FILTER (WHERE o.org_ips < 10) / count(*), 1)
        AS pct_org_has_under_10_ips,
      round(100.0 * count(*) FILTER (WHERE cloud_provider IS NOT NULL) / count(*), 1)
        AS pct_cloud_provider
    FROM banner b JOIN o USING (org)""",
    "O1. org/isp: how often is org a large network?",
)
show(
    con,
    """SELECT org, count(DISTINCT ip) AS ips, count(*) AS records FROM banner
    GROUP BY org ORDER BY ips DESC LIMIT 15""",
    "O2. top orgs by distinct IP",
)
show(
    con,
    r"""WITH h AS (SELECT lower(org) AS org, unnest(domains) AS d FROM banner
              WHERE len(domains) > 0 AND org IS NOT NULL)
    SELECT count(*) AS record_domains,
      round(100.0 * count(*) FILTER (WHERE contains(org,
            split_part(d, '.', 1)) AND length(split_part(d, '.', 1)) >= 4) / count(*), 1)
        AS pct_org_contains_domain_label
    FROM h""",
    "O3. does org name the same entity as the hostname domain? (crude: org contains the "
    "domain's first label)",
)
# hostnames
show(
    con,
    r"""WITH h AS (SELECT ip, asn, unnest(hostnames) AS host, unnest(domains) AS dom
              FROM banner WHERE len(hostnames) > 0 AND len(hostnames) = len(domains))
    SELECT count(*) AS hostnames,
      round(100.0 * count(*) FILTER (WHERE regexp_matches(host,
            '\d{1,3}[-.x]\d{1,3}[-.x]\d{1,3}')) / count(*), 1) AS pct_iplike,
      round(100.0 * count(*) FILTER (WHERE contains(host, replace(ip, '.', '-'))
            OR contains(host, replace(ip, '.', '.'))) / count(*), 1) AS pct_contains_own_ip
    FROM h""",
    "N1. hostnames: IP-like share",
)
show(
    con,
    r"""WITH h AS (SELECT DISTINCT ip, asn, unnest(domains) AS dom FROM banner
              WHERE len(domains) > 0),
    a AS (SELECT asn, count(DISTINCT ip) AS asn_ips FROM h GROUP BY asn),
    ad AS (SELECT asn, dom, count(DISTINCT ip) AS dom_ips FROM h GROUP BY ALL),
    top AS (SELECT ad.asn, ad.dom, dom_ips, asn_ips FROM ad JOIN a USING (asn)
            QUALIFY row_number() OVER (PARTITION BY ad.asn ORDER BY dom_ips DESC) = 1)
    SELECT count(*) AS ip_domain_pairs,
      round(100.0 * count(*) FILTER (WHERE (h.asn, h.dom) IN (SELECT (asn, dom) FROM top
             WHERE dom_ips >= 50 AND dom_ips >= 0.3 * asn_ips)) / count(*), 1)
        AS pct_dominant_asn_domain
    FROM h""",
    "N2. share of (IP, domain) pairs whose domain is its ASN's dominant domain "
    "(>=50 IPs and >=30% of the ASN's named IPs)",
)
show(
    con,
    r"""WITH h AS (SELECT DISTINCT ip, asn, org, unnest(domains) AS dom FROM banner
              WHERE len(domains) > 0)
    SELECT dom, any_value(org) AS an_org, count(DISTINCT ip) AS ips FROM h
    GROUP BY dom ORDER BY ips DESC LIMIT 20""",
    "N3. top hostname domains by distinct IP",
)
# DuckDB traps
show(
    con,
    """SELECT count_if(x) AS count_if_all_null, count(*) FILTER (WHERE x) AS filter_all_null,
      least(NULL, 3) AS least_null_3, greatest(NULL, 3) AS greatest_null_3
    FROM (SELECT CAST(NULL AS BOOLEAN) AS x FROM range(3))""",
    "D1. DuckDB count_if / least on NULL input",
)
show(
    con,
    "SELECT count_if(x) AS count_if_empty_input FROM (SELECT true AS x WHERE false)",
    "D2. count_if on zero rows",
)
show(con, "SELECT version() AS duckdb_version", "D3. DuckDB version")
# Correlated evidence
show(
    con,
    """SELECT list_contains(tags, 'eol-product') AS eol_tag,
      cves IS NOT NULL AND len(cves) > 0 AS has_cves, count(*) AS records
    FROM banner WHERE cpe23 IS NOT NULL AND len(cpe23) > 0 GROUP BY ALL ORDER BY ALL""",
    "R1. eol-product tag vs CVE list, among records with a CPE",
)
show(
    con,
    f"""SELECT count(*) AS ips_with_any_record, sum(ip_records) AS records,
      round(sum(ip_records)::DOUBLE / count(*), 2) AS records_per_ip
    FROM '{stats}'""",
    "R2. records per IP overall",
)
