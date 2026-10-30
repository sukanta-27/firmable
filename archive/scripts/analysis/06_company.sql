-- build company table (other+cloud buckets, cdn records kept only as a maturity marker)
CREATE TABLE comp AS
SELECT a.company_key, mode(a.route) AS route, mode(a.owner_class) AS owner_class, mode(a.country_code) AS country,
  count(*) AS recs, count(DISTINCT a.ip) AS ips, count(DISTINCT s.port) AS ports,
  count(*) FILTER (WHERE a.bucket = 'cdn') AS cdn_recs,
  count(*) FILTER (WHERE s.vuln_verified) AS v_verified, count(*) FILTER (WHERE s.vuln_kev_verified) AS v_kev_verified, count(*) FILTER (WHERE s.vuln_kev) AS v_kev,
  count(*) FILTER (WHERE s.vuln_ransomware) AS v_ransom, count(*) FILTER (WHERE s.vuln_cvss9) AS v_cvss9, count(*) FILTER (WHERE s.vuln_any) AS v_any,
  count(*) FILTER (WHERE s.eol_product) AS eol, count(*) FILTER (WHERE s.eol_os) AS eol_os, count(*) FILTER (WHERE s.cert_expired) AS cert_expired,
  count(*) FILTER (WHERE s.cert_self_signed) AS self_signed, count(*) FILTER (WHERE s.tls_1_0_1_1) AS tls_old, count(*) FILTER (WHERE s.ssl_v2_v3) AS sslv23,
  count(*) FILTER (WHERE s.weak_cipher) AS weak_cipher, count(*) FILTER (WHERE s.rsa_lt_2048) AS rsa_weak, count(*) FILTER (WHERE s.heartbleed) AS heartbleed,
  count(*) FILTER (WHERE s.rdp) AS rdp, count(*) FILTER (WHERE s.rdp_no_nla) AS rdp_no_nla, count(*) FILTER (WHERE s.vnc) AS vnc, count(*) FILTER (WHERE s.vnc_noauth) AS vnc_noauth, count(*) FILTER (WHERE s.telnet) AS telnet,
  count(*) FILTER (WHERE s.ics AND s.owner_class NOT IN ('hosting', 'cdn', 'proxy', 'vpn')) AS ics_real,
  count(*) FILTER (WHERE s.ssh_weak_algos) AS ssh_weak, count(*) FILTER (WHERE s.smb) AS smb, count(*) FILTER (WHERE s.smb_v1) AS smb_v1, count(*) FILTER (WHERE s.smb_anonymous) AS smb_anon,
  count(*) FILTER (WHERE s.ftp) AS ftp, count(*) FILTER (WHERE s.ftp_anonymous) AS ftp_anon, count(*) FILTER (WHERE s.db_exposed) AS db, count(*) FILTER (WHERE s.db_no_auth) AS db_noauth,
  count(*) FILTER (WHERE s.devops_exposed) AS devops, count(*) FILTER (WHERE s.metrics_exposed) AS metrics, count(*) FILTER (WHERE s.vpn_edge) AS vpn,
  count(*) FILTER (WHERE s.named_edge_appliance) AS edge_appl, count(*) FILTER (WHERE s.oob_mgmt) AS oob, count(*) FILTER (WHERE s.router_mgmt) AS router,
  count(*) FILTER (WHERE s.cameras_dvr) AS cams, count(*) FILTER (WHERE s.nas_storage) AS nas, count(*) FILTER (WHERE s.printers) AS printers, count(*) FILTER (WHERE s.ics) AS ics,
  count(*) FILTER (WHERE s.medical_tag OR s.dicom_product) AS medical, count(*) FILTER (WHERE s.ai_infra) AS ai, count(*) FILTER (WHERE s.compromise) AS compromise,
  count(*) FILTER (WHERE s.open_dir) AS open_dir, count(*) FILTER (WHERE s.web_default_page) AS default_page, count(*) FILTER (WHERE s.web_index_of) AS index_of,
  count(*) FILTER (WHERE s.web_admin_panel) AS admin_panel, count(*) FILTER (WHERE s.web_defaced) AS defaced,
  count(*) FILTER (WHERE s.http_200) AS http200, count(*) FILTER (WHERE s.web_hsts) AS hsts, count(*) FILTER (WHERE s.web_csp) AS csp, count(*) FILTER (WHERE s.securitytxt) AS sectxt,
  count(*) FILTER (WHERE s.waf) AS waf, count(*) FILTER (WHERE s.pqc) AS pqc, count(*) FILTER (WHERE s.has_ssl) AS ssl_recs
FROM read_parquet('archive/data/work/attr.parquet') a JOIN s USING (rec_id)
WHERE a.company_key IS NOT NULL AND a.bucket IN ('other', 'cloud', 'cdn')
GROUP BY 1;
-- companies and estate sizes (non-cdn records only)
SELECT count(*) companies, count(*) FILTER (WHERE recs - cdn_recs > 0) with_non_cdn_records, count(*) FILTER (WHERE ips >= 5) ips_ge_5, count(*) FILTER (WHERE ips >= 20) ips_ge_20,
       count(*) FILTER (WHERE route IN ('org_label', 'sni', 'cert_o', 'domain')) high_conf_route FROM comp;
-- signal prevalence at company level: companies with at least one flagged record
WITH f AS (SELECT route IN ('org_label', 'sni', 'cert_o', 'domain') AS hc, * FROM comp WHERE recs - cdn_recs > 0),
agg AS (
  SELECT count(*) AS companies, count(*) FILTER (WHERE hc) AS companies_hc,
    count(*) FILTER (WHERE v_kev_verified > 0) v_kev_verified, count(*) FILTER (WHERE v_verified > 0) v_verified, count(*) FILTER (WHERE v_kev > 0) v_kev, count(*) FILTER (WHERE v_ransom > 0) v_ransom,
    count(*) FILTER (WHERE v_cvss9 > 0) v_cvss9, count(*) FILTER (WHERE v_any > 0) v_any, count(*) FILTER (WHERE eol > 0) eol, count(*) FILTER (WHERE eol_os > 0) eol_os,
    count(*) FILTER (WHERE cert_expired > 0) cert_expired, count(*) FILTER (WHERE self_signed > 0) self_signed, count(*) FILTER (WHERE tls_old > 0) tls_old, count(*) FILTER (WHERE sslv23 > 0) sslv23,
    count(*) FILTER (WHERE weak_cipher > 0) weak_cipher, count(*) FILTER (WHERE rsa_weak > 0) rsa_weak, count(*) FILTER (WHERE heartbleed > 0) heartbleed, count(*) FILTER (WHERE rdp > 0) rdp,
    count(*) FILTER (WHERE rdp_no_nla > 0) rdp_no_nla, count(*) FILTER (WHERE vnc > 0) vnc, count(*) FILTER (WHERE telnet > 0) telnet, count(*) FILTER (WHERE ssh_weak > 0) ssh_weak,
    count(*) FILTER (WHERE smb > 0) smb, count(*) FILTER (WHERE smb_v1 > 0) smb_v1, count(*) FILTER (WHERE smb_anon > 0) smb_anon, count(*) FILTER (WHERE ftp > 0) ftp, count(*) FILTER (WHERE ftp_anon > 0) ftp_anon,
    count(*) FILTER (WHERE db > 0) db, count(*) FILTER (WHERE db_noauth > 0) db_noauth, count(*) FILTER (WHERE devops > 0) devops, count(*) FILTER (WHERE metrics > 0) metrics, count(*) FILTER (WHERE vpn > 0) vpn,
    count(*) FILTER (WHERE edge_appl > 0) edge_appl, count(*) FILTER (WHERE oob > 0) oob, count(*) FILTER (WHERE router > 0) router, count(*) FILTER (WHERE cams > 0) cams, count(*) FILTER (WHERE nas > 0) nas,
    count(*) FILTER (WHERE printers > 0) printers, count(*) FILTER (WHERE ics > 0) ics, count(*) FILTER (WHERE ics_real > 0) ics_real, count(*) FILTER (WHERE vnc_noauth > 0) vnc_noauth,
    count(*) FILTER (WHERE medical > 0) medical, count(*) FILTER (WHERE ai > 0) ai, count(*) FILTER (WHERE compromise > 0) compromise,
    count(*) FILTER (WHERE open_dir > 0) open_dir, count(*) FILTER (WHERE default_page > 0) default_page, count(*) FILTER (WHERE index_of > 0) index_of, count(*) FILTER (WHERE admin_panel > 0) admin_panel,
    count(*) FILTER (WHERE defaced > 0) defaced, count(*) FILTER (WHERE hsts > 0) hsts, count(*) FILTER (WHERE csp > 0) csp, count(*) FILTER (WHERE sectxt > 0) sectxt, count(*) FILTER (WHERE waf > 0) waf, count(*) FILTER (WHERE cdn_recs > 0) uses_cdn
  FROM f
)
SELECT name AS signal, value AS companies, round(100.0 * value / (SELECT companies FROM agg), 2) AS pct_companies
FROM (UNPIVOT agg ON COLUMNS(* EXCLUDE (companies, companies_hc)) INTO NAME name VALUE value)
ORDER BY companies DESC;
-- same, restricted to companies with >= 5 ips (an estate, not a single box)
WITH f AS (SELECT * FROM comp WHERE recs - cdn_recs > 0 AND ips >= 5),
agg AS (
  SELECT count(*) AS companies,
    count(*) FILTER (WHERE v_kev_verified > 0) v_kev_verified, count(*) FILTER (WHERE v_verified > 0) v_verified, count(*) FILTER (WHERE v_kev > 0) v_kev, count(*) FILTER (WHERE v_ransom > 0) v_ransom,
    count(*) FILTER (WHERE eol > 0) eol, count(*) FILTER (WHERE cert_expired > 0) cert_expired, count(*) FILTER (WHERE self_signed > 0) self_signed, count(*) FILTER (WHERE tls_old > 0) tls_old,
    count(*) FILTER (WHERE heartbleed > 0) heartbleed, count(*) FILTER (WHERE rdp > 0) rdp, count(*) FILTER (WHERE rdp_no_nla > 0) rdp_no_nla, count(*) FILTER (WHERE vnc > 0) vnc, count(*) FILTER (WHERE telnet > 0) telnet,
    count(*) FILTER (WHERE smb_v1 > 0) smb_v1, count(*) FILTER (WHERE smb_anon > 0) smb_anon, count(*) FILTER (WHERE ftp_anon > 0) ftp_anon, count(*) FILTER (WHERE db > 0) db, count(*) FILTER (WHERE db_noauth > 0) db_noauth,
    count(*) FILTER (WHERE devops > 0) devops, count(*) FILTER (WHERE metrics > 0) metrics, count(*) FILTER (WHERE edge_appl > 0) edge_appl, count(*) FILTER (WHERE oob > 0) oob, count(*) FILTER (WHERE cams > 0) cams,
    count(*) FILTER (WHERE nas > 0) nas, count(*) FILTER (WHERE printers > 0) printers, count(*) FILTER (WHERE ics > 0) ics, count(*) FILTER (WHERE medical > 0) medical, count(*) FILTER (WHERE ai > 0) ai,
    count(*) FILTER (WHERE compromise > 0) compromise, count(*) FILTER (WHERE open_dir > 0) open_dir, count(*) FILTER (WHERE default_page > 0) default_page, count(*) FILTER (WHERE admin_panel > 0) admin_panel,
    count(*) FILTER (WHERE hsts > 0) hsts, count(*) FILTER (WHERE sectxt > 0) sectxt, count(*) FILTER (WHERE waf > 0) waf, count(*) FILTER (WHERE cdn_recs > 0) uses_cdn
  FROM f
)
SELECT name AS signal, value AS companies_ge5ips, round(100.0 * value / (SELECT companies FROM agg), 2) AS pct
FROM (UNPIVOT agg ON COLUMNS(* EXCLUDE (companies)) INTO NAME name VALUE value)
ORDER BY companies_ge5ips DESC;
-- co-occurrence: does neglect cluster? lift of signal B given signal A, companies with >= 5 ips
WITH f AS (SELECT * FROM comp WHERE recs - cdn_recs > 0 AND ips >= 5),
pairs AS (
  SELECT 'eol -> rdp_no_nla' pair, avg(CASE WHEN eol > 0 THEN (rdp_no_nla > 0)::INT END) p_given, avg((rdp_no_nla > 0)::INT) p_base FROM f
  UNION ALL SELECT 'eol -> cert_expired', avg(CASE WHEN eol > 0 THEN (cert_expired > 0)::INT END), avg((cert_expired > 0)::INT) FROM f
  UNION ALL SELECT 'eol -> v_verified', avg(CASE WHEN eol > 0 THEN (v_verified > 0)::INT END), avg((v_verified > 0)::INT) FROM f
  UNION ALL SELECT 'cert_expired -> db', avg(CASE WHEN cert_expired > 0 THEN (db > 0)::INT END), avg((db > 0)::INT) FROM f
  UNION ALL SELECT 'default_page -> v_verified', avg(CASE WHEN default_page > 0 THEN (v_verified > 0)::INT END), avg((v_verified > 0)::INT) FROM f
  UNION ALL SELECT 'rdp -> smb', avg(CASE WHEN rdp > 0 THEN (smb > 0)::INT END), avg((smb > 0)::INT) FROM f
  UNION ALL SELECT 'waf -> v_verified', avg(CASE WHEN waf > 0 THEN (v_verified > 0)::INT END), avg((v_verified > 0)::INT) FROM f
  UNION ALL SELECT 'hsts -> eol', avg(CASE WHEN hsts > 0 THEN (eol > 0)::INT END), avg((eol > 0)::INT) FROM f
  UNION ALL SELECT 'waf -> rdp_no_nla', avg(CASE WHEN waf > 0 THEN (rdp_no_nla > 0)::INT END), avg((rdp_no_nla > 0)::INT) FROM f
  UNION ALL SELECT 'cams -> telnet', avg(CASE WHEN cams > 0 THEN (telnet > 0)::INT END), avg((telnet > 0)::INT) FROM f
)
SELECT pair, round(100 * p_given, 1) pct_given, round(100 * p_base, 1) pct_base, round(p_given / p_base, 2) lift FROM pairs;
-- v0 priority score: hand weights, severity-first, estate-normalised evidence lines
CREATE TABLE ranked AS
SELECT company_key, route, owner_class, country, ips, recs - cdn_recs AS exposed_recs,
  10 * least(v_kev_verified, 3) + 6 * least(v_verified, 3) + 10 * least(compromise, 2) + 6 * least(heartbleed, 2)
  + 8 * least(db_noauth, 3) + 5 * least(smb_v1, 2) + 5 * least(smb_anon, 2) + 3 * least(ftp_anon, 2)
  + 5 * least(rdp_no_nla, 3) + 2 * least(rdp, 3) + 3 * least(vnc, 2) + 8 * least(vnc_noauth, 2) + 3 * least(telnet, 2) + 2 * least(devops, 2)
  + 5 * least(oob, 2) + 6 * least(ics_real, 2) + 5 * least(medical, 2) + 3 * least(ai, 2) + 3 * least(open_dir, 2)
  + 3 * least(eol, 3) + 3 * least(eol_os, 2) + 2 * least(cert_expired, 2) + 2 * least(sslv23, 2) + 2 * least(rsa_weak, 2)
  + 2 * least(cams, 2) + 2 * least(nas, 2) + 2 * least(printers, 2) + 1 * least(default_page, 2) + 1 * least(admin_panel, 2)
  + CASE WHEN edge_appl > 0 AND v_kev > 0 THEN 4 ELSE 0 END
  - 2 * least(hsts, 2) - 2 * least(sectxt, 1) - 2 * least(waf, 2)                                    AS score,
  v_kev_verified, v_verified, compromise, heartbleed, db_noauth, smb_v1, smb_anon, ftp_anon, rdp_no_nla, rdp, vnc, vnc_noauth, telnet, devops, oob,
  ics, ics_real, medical, ai, open_dir, eol, eol_os, cert_expired, cams, nas, printers, default_page, hsts, sectxt, waf
FROM comp WHERE recs - cdn_recs > 0;
-- score distribution among high-confidence companies with >= 2 ips
SELECT count(*) companies, quantile_cont(score, 0.5) p50, quantile_cont(score, 0.9) p90, quantile_cont(score, 0.99) p99, max(score) mx,
       count(*) FILTER (WHERE score >= 20) score_ge_20, count(*) FILTER (WHERE score >= 40) score_ge_40
FROM ranked WHERE route IN ('org_label', 'sni', 'cert_o', 'domain') AND ips >= 2;
-- top 40 by score, high-confidence routes, >= 2 ips
SELECT company_key, route, owner_class, country, ips, exposed_recs, score,
       v_kev_verified kevv, v_verified vv, compromise c2, db_noauth dbna, smb_v1, rdp_no_nla rdpnn, rdp, vnc, telnet, devops, oob, ics, medical, ai, open_dir od, eol, cert_expired cexp, cams, hsts, waf
FROM ranked WHERE route IN ('org_label', 'sni', 'cert_o', 'domain') AND ips >= 2
ORDER BY score DESC, ips DESC LIMIT 40;
-- companies with a verified known-exploited finding (high-confidence routes), with the CVEs
SELECT a.company_key, mode(a.route) route, mode(a.owner_class) owner_class, mode(a.country_code) cc,
       count(DISTINCT a.ip) ips_affected, list_distinct(list(v.cve)) cves, mode(b.product) product
FROM vulns v JOIN read_parquet('archive/data/work/attr.parquet') a USING (rec_id) JOIN b USING (rec_id)
WHERE v.verified AND v.kev AND a.bucket IN ('other', 'cloud') AND a.route IN ('org_label', 'sni', 'cert_o', 'domain')
GROUP BY 1 ORDER BY ips_affected DESC LIMIT 30;
-- verified-KEV: how many companies, by route confidence
SELECT a.route IN ('org_label', 'sni', 'cert_o', 'domain') AS high_conf, count(DISTINCT a.company_key) companies, count(DISTINCT a.ip) ips, count(*) recs
FROM vulns v JOIN read_parquet('archive/data/work/attr.parquet') a USING (rec_id)
WHERE v.verified AND v.kev AND a.bucket IN ('other', 'cloud') AND a.company_key IS NOT NULL GROUP BY 1;
-- persist
COPY (SELECT * FROM comp) TO 'archive/data/work/comp.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
COPY (SELECT * FROM ranked) TO 'archive/data/work/ranked.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
