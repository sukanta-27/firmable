"""Step 4. What a CVE on a record means: verified vs unverified, and the kev, epss,
ransomware_campaign and cvss fields against CISA KEV (catalog 2026.10.27) and FIRST EPSS
(score_date 2026-10-27) in data/external/.
Run: uv run python archive/blind-analysis/scripts/05_vuln_fields.py sample|full
"""

from _db import ROOT, connect, show

con, ds = connect()
ext = ROOT / "data" / "external"
con.execute(
    f"""CREATE TEMP TABLE cisa AS
    SELECT v.cveID AS cve, CAST(v.dateAdded AS DATE) AS date_added,
           v.knownRansomwareCampaignUse AS ransomware
    FROM (SELECT unnest(vulnerabilities) AS v FROM read_json('{ext}/kev.json'))"""
)
con.execute(
    f"""CREATE TEMP TABLE first_epss AS
    SELECT cve, epss AS epss_first, percentile AS pct_first
    FROM read_csv('{ext}/epss_scores-current.csv.gz', skip=1, header=true)"""
)
print(f"dataset={ds}")

show(
    con,
    """SELECT count(*) AS entries, count(DISTINCT rec_id) AS records,
      count(DISTINCT cve) AS cves,
      count(*) FILTER (WHERE verified) AS verified_entries,
      count(DISTINCT rec_id) FILTER (WHERE verified) AS records_with_verified,
      count(DISTINCT cve) FILTER (WHERE verified) AS verified_cves,
      round(100.0 * count(*) FILTER (WHERE verified) / count(*), 4) AS pct_verified
    FROM vuln""",
    "4a. entries, verified share",
)
show(
    con,
    """SELECT verified, kev, count(*) AS entries FROM vuln GROUP BY ALL ORDER BY entries DESC""",
    "4b. kev x verified (kev is NULL on most unverified entries)",
)
show(
    con,
    """WITH b AS (SELECT cve, bool_or(kev) AS bronze_kev FROM vuln GROUP BY cve)
    SELECT coalesce(bronze_kev, false) AS bronze_kev_any, c.cve IS NOT NULL AS in_cisa_kev,
           count(*) AS cves
    FROM b LEFT JOIN cisa c USING (cve) GROUP BY ALL ORDER BY ALL""",
    "4c. per CVE: bronze kev flag vs membership in CISA KEV 2026.10.27",
)
show(
    con,
    """WITH b AS (SELECT cve, bool_or(kev) AS bronze_kev, count(*) AS entries,
                         count(*) FILTER (WHERE verified) AS verified_entries
                  FROM vuln GROUP BY cve)
    SELECT c.cve, c.date_added, coalesce(b.bronze_kev, false) AS bronze_kev, b.entries,
           b.verified_entries
    FROM cisa c JOIN b USING (cve)
    WHERE NOT coalesce(b.bronze_kev, false) OR c.date_added >= DATE '2026-10-20'
    ORDER BY c.date_added DESC, c.cve LIMIT 40""",
    "4d. CVEs in CISA KEV whose bronze kev flag is not true, or added since 2026-10-20",
)
show(
    con,
    """WITH b AS (SELECT cve, any_value(ransomware_campaign) AS rc,
                         count(DISTINCT ransomware_campaign) AS n_rc
                  FROM vuln WHERE ransomware_campaign IS NOT NULL GROUP BY cve)
    SELECT b.rc AS bronze_ransomware, c.ransomware AS cisa_ransomware, count(*) AS cves,
           max(n_rc) AS max_values_per_cve
    FROM b LEFT JOIN cisa c USING (cve) GROUP BY ALL ORDER BY cves DESC""",
    "4e. ransomware_campaign vs CISA knownRansomwareCampaignUse",
)
show(
    con,
    """WITH b AS (SELECT cve, min(epss) AS mn, max(epss) AS mx, any_value(epss) AS e,
                         min(cvss) AS cmin, max(cvss) AS cmax
                  FROM vuln GROUP BY cve)
    SELECT count(*) AS cves,
      count(*) FILTER (WHERE mn <> mx) AS cves_epss_varies_across_records,
      count(*) FILTER (WHERE cmin <> cmax) AS cves_cvss_varies_across_records,
      count(f.cve) AS cves_in_first,
      round(corr(e, epss_first), 4) AS corr_epss_vs_first,
      round(quantile_cont(abs(e - epss_first), 0.5), 5) AS median_abs_diff,
      round(quantile_cont(abs(e - epss_first), 0.99), 5) AS p99_abs_diff,
      count(*) FILTER (WHERE abs(e - epss_first) > 0.1) AS cves_diff_gt_0_1
    FROM b LEFT JOIN first_epss f USING (cve)""",
    "4f. epss and cvss: constant per CVE? bronze epss vs FIRST 2026-10-27",
)
show(
    con,
    """WITH r AS (SELECT rec_id, count(*) AS n, bool_or(verified) AS any_verified
               FROM vuln GROUP BY rec_id)
    SELECT any_verified, count(*) AS records,
           quantile_cont(n, [0.5, 0.9, 0.99]) AS cves_per_record_q, max(n) AS max_cves
    FROM r GROUP BY ALL""",
    "4g. CVEs per record, records with vs without a verified CVE",
)
show(
    con,
    """WITH r AS (SELECT rec_id, md5(string_agg(cve, ',' ORDER BY cve)) AS cve_set
               FROM vuln GROUP BY rec_id),
    j AS (SELECT b.rec_id, array_to_string(list_sort(b.cpe23), ',') AS cpes, b.version,
                 b.product, r.cve_set
          FROM banner b JOIN r USING (rec_id))
    SELECT count(*) AS records_with_cves,
      count(*) FILTER (WHERE cpes IS NOT NULL AND cpes <> '') AS with_cpe23,
      count(*) FILTER (WHERE version IS NOT NULL) AS with_version,
      (SELECT count(*) FROM (SELECT cpes FROM j GROUP BY cpes)) AS distinct_cpe_sets,
      (SELECT count(*) FROM (SELECT cpes FROM j GROUP BY cpes
                             HAVING count(DISTINCT cve_set) = 1)) AS cpe_sets_with_one_cve_set,
      (SELECT sum(c) FROM (SELECT count(*) AS c FROM j GROUP BY cpes
                           HAVING count(DISTINCT cve_set) = 1)) AS records_in_those
    FROM j""",
    "4h. Is the CVE list a function of the CPE list? (one CVE set per CPE set => inferred)",
)
show(
    con,
    """WITH r AS (SELECT rec_id, md5(string_agg(cve, ',' ORDER BY cve)) AS cve_set,
                      bool_or(verified) AS v
               FROM vuln GROUP BY rec_id),
    j AS (SELECT array_to_string(list_sort(b.cpe23), ',') AS cpes, r.cve_set
          FROM banner b JOIN r USING (rec_id) WHERE NOT r.v)
    SELECT cpes, count(*) AS records, count(DISTINCT cve_set) AS distinct_cve_sets
    FROM j GROUP BY cpes ORDER BY records DESC LIMIT 15""",
    "4i. top CPE sets among unverified-CVE records, and how many CVE sets each carries",
)
show(
    con,
    """SELECT b.product, count(DISTINCT b.rec_id) AS records, count(*) AS entries,
           count(*) FILTER (WHERE v.kev) AS kev_entries
    FROM vuln v JOIN banner b USING (rec_id) WHERE NOT v.verified
    GROUP BY 1 ORDER BY entries DESC LIMIT 15""",
    "4j. products carrying unverified CVE entries",
)
show(
    con,
    """SELECT v.cve, b.product, count(*) AS records
    FROM vuln v JOIN banner b USING (rec_id) WHERE v.verified
    GROUP BY ALL ORDER BY records DESC LIMIT 40""",
    "4k. verified CVEs by product",
)
show(
    con,
    """WITH ov AS (
      SELECT rec_id, unnest(json_extract_string(opts, '$.vulns[*]')) AS cve FROM banner
      WHERE json_array_length(json_extract(opts, '$.vulns')) > 0),
    vv AS (SELECT rec_id, cve FROM vuln WHERE verified)
    SELECT CASE WHEN ov.cve IS NULL THEN 'verified only'
                WHEN vv.cve IS NULL THEN 'opts.vulns only' ELSE 'both' END AS where_found,
           coalesce(ov.cve, vv.cve) AS cve, count(*) AS records
    FROM ov FULL JOIN vv USING (rec_id, cve)
    WHERE ov.cve IS NULL OR vv.cve IS NULL
    GROUP BY ALL ORDER BY records DESC""",
    "4l. opts.vulns (scanner's own test list) vs verified, where they differ",
)
show(
    con,
    """SELECT cve, cvss, cvss_version, epss, ranking_epss, kev, ransomware_campaign,
           count(*) AS entries
    FROM vuln WHERE cve IN ('CVE-2021-44228', 'CVE-2024-6387', 'CVE-2023-44487',
                            'CVE-2019-0708', 'CVE-2020-0796', 'CVE-2014-0160')
    GROUP BY ALL ORDER BY cve, entries DESC LIMIT 30""",
    "4m. field values for a few well-known CVEs",
)
show(
    con,
    """SELECT cve, count(*) AS entries, count(*) FILTER (WHERE verified) AS verified_entries
    FROM vuln WHERE kev AND cve NOT IN (SELECT cve FROM cisa) GROUP BY 1""",
    "4n. IDs flagged kev in bronze but absent from CISA KEV",
)
show(
    con,
    """SELECT cve, count(*) AS entries,
      round(100.0 * count(*) / sum(count(*)) OVER (), 1) AS pct_of_kev_unverified
    FROM vuln WHERE kev AND NOT verified GROUP BY 1 ORDER BY 2 DESC LIMIT 5""",
    "4o. which CVEs make up the kev flag on unverified entries",
)
