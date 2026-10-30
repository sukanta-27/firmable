-- records and IPs by bucket
SELECT bucket, count(*) AS recs, count(DISTINCT ip) AS ips FROM b GROUP BY 1 ORDER BY 2 DESC;
-- identity fields, all records
SELECT count(*) AS recs,
  count(DISTINCT coalesce(ip_str, ipv6)) AS ips,
  count(DISTINCT asn) AS asns,
  count(*) FILTER (WHERE org IS NOT NULL AND isp IS NOT NULL AND org <> isp) AS org_ne_isp,
  count(*) FILTER (WHERE len(domains) > 0) AS has_domain,
  count(*) FILTER (WHERE len(hostnames) > 0) AS has_hostname,
  count(*) FILTER (WHERE sni_hostname IS NOT NULL) AS sni_scan,
  count(*) FILTER (WHERE len(cpe23) > 0) AS has_cpe,
  count(*) FILTER (WHERE has_ssl) AS has_ssl,
  count(*) FILTER (WHERE has_http) AS has_http,
  count(DISTINCT ssl_jarm) AS jarm_distinct,
  count(*) FILTER (WHERE ssl_jarm IS NOT NULL) AS jarm_recs,
  count(DISTINCT ssl_ja3s) AS ja3s_distinct,
  count(*) FILTER (WHERE ssh_hassh IS NOT NULL) AS hassh_recs,
  count(DISTINCT ssh_hassh) AS hassh_distinct
FROM b
;
-- signals by bucket
SELECT sig, count(*) FILTER (WHERE bucket <> 'honeypot') AS recs_excl_honeypot,
       count(*) FILTER (WHERE bucket = 'other') AS recs_other,
       count(DISTINCT ip) FILTER (WHERE bucket = 'other') AS ips_other,
       count(*) FILTER (WHERE bucket = 'cdn') AS recs_cdn
FROM (
  SELECT bucket, ip, unnest([
    CASE WHEN vuln_any THEN 'vuln_any' END, CASE WHEN vuln_verified THEN 'vuln_verified' END,
    CASE WHEN vuln_kev THEN 'vuln_kev' END, CASE WHEN vuln_kev_verified THEN 'vuln_kev_verified' END,
    CASE WHEN vuln_ransomware THEN 'vuln_ransomware_known' END, CASE WHEN vuln_cvss9 THEN 'vuln_cvss9' END,
    CASE WHEN vuln_epss50 THEN 'vuln_epss50' END,
    CASE WHEN eol_product THEN 'eol_product' END, CASE WHEN eol_os THEN 'eol_os' END,
    CASE WHEN cert_expired THEN 'cert_expired' END, CASE WHEN cert_self_signed THEN 'cert_self_signed' END,
    CASE WHEN tls_1_0_1_1 THEN 'tls_1_0_1_1' END, CASE WHEN ssl_v2_v3 THEN 'ssl_v2_v3' END,
    CASE WHEN heartbleed THEN 'heartbleed' END,
    CASE WHEN rdp THEN 'rdp' END, CASE WHEN rdp_no_nla THEN 'rdp_no_nla' END,
    CASE WHEN vnc THEN 'vnc' END, CASE WHEN vnc_noauth THEN 'vnc_noauth' END,
    CASE WHEN telnet THEN 'telnet' END,
    CASE WHEN smb THEN 'smb' END, CASE WHEN smb_v1 THEN 'smb_v1' END, CASE WHEN smb_anonymous THEN 'smb_anonymous' END,
    CASE WHEN ftp THEN 'ftp' END, CASE WHEN ftp_anonymous THEN 'ftp_anonymous' END,
    CASE WHEN oob_mgmt THEN 'oob_mgmt' END,
    CASE WHEN compromise THEN 'compromise' END,
    CASE WHEN waf THEN 'waf' END, CASE WHEN web_hsts THEN 'web_hsts' END, CASE WHEN web_csp THEN 'web_csp' END,
    CASE WHEN http_200 THEN 'http_200' END,
    CASE WHEN securitytxt THEN 'securitytxt' END, CASE WHEN pqc THEN 'pqc' END,
    CASE WHEN has_ssl THEN 'has_ssl' END
  ]) AS sig FROM s
) WHERE sig IS NOT NULL GROUP BY 1 ORDER BY 1
;
-- cvss version mix
SELECT cvss_version, count(*) AS rows_, count(DISTINCT cve) AS cves, round(avg(cvss),2) AS avg_cvss FROM vulns GROUP BY 1 ORDER BY 1;
-- vulns totals
SELECT count(*) AS rows_, count(DISTINCT rec_id) AS recs, count(DISTINCT cve) AS cves,
  count(DISTINCT cve) FILTER (WHERE kev) AS kev_cves,
  count(*) FILTER (WHERE kev) AS kev_rows,
  count(*) FILTER (WHERE verified) AS verified_rows,
  count(DISTINCT rec_id) FILTER (WHERE verified) AS verified_recs,
  count(DISTINCT cve) FILTER (WHERE verified) AS verified_cves,
  count(DISTINCT cve) FILTER (WHERE ransomware_campaign = 'Known') AS ransom_known_cves,
  count(*) FILTER (WHERE cvss IS NULL) AS cvss_null, count(*) FILTER (WHERE epss IS NULL) AS epss_null
FROM vulns;
-- top KEV CVEs by records with verified share
SELECT cve, count(*) AS recs, count(*) FILTER (WHERE verified) AS verified, any_value(cvss) AS cvss, any_value(epss) AS epss
FROM vulns WHERE kev GROUP BY 1 ORDER BY 2 DESC LIMIT 5;
-- verified CVEs by records
SELECT cve, count(*) AS recs, any_value(kev) AS kev, any_value(cvss) AS cvss, any_value(epss) AS epss
FROM vulns WHERE verified GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
-- embedded EPSS vs FIRST feed of 2026-10-27
SELECT count(*) AS cves, round(corr(v.epss, e.epss),4) AS corr, round(avg(abs(v.epss - e.epss)),5) AS mad,
  count(*) FILTER (WHERE abs(v.epss - e.epss) > 0.1) AS diff_gt_0_1
FROM (SELECT cve, any_value(epss) AS epss FROM vulns GROUP BY 1) v JOIN epss e USING (cve);
-- embedded kev flag vs CISA catalog 2026.10.27
SELECT count(*) FILTER (WHERE v.kev AND k.cve IS NOT NULL) AS both_,
  count(*) FILTER (WHERE v.kev AND k.cve IS NULL) AS shodan_only,
  count(*) FILTER (WHERE NOT v.kev AND k.cve IS NOT NULL) AS catalog_only
FROM (SELECT cve, bool_or(coalesce(kev,false)) AS kev FROM vulns GROUP BY 1) v LEFT JOIN kev k USING (cve);
-- cves per record
SELECT median(n_vulns) AS med, quantile_cont(n_vulns, 0.9) AS p90, max(n_vulns) AS mx FROM banners WHERE n_vulns > 0;
-- heartbleed field vs verified CVE-2014-0160
SELECT count(*) FILTER (WHERE opts_heartbleed ILIKE '%VULNERABLE%') AS hb_field_vuln,
  count(*) FILTER (WHERE opts_heartbleed IS NOT NULL) AS hb_tested FROM banners;
SELECT count(*) AS cve_2014_0160_rows, count(*) FILTER (WHERE verified) AS verified FROM vulns WHERE cve = 'CVE-2014-0160'
;
-- products behind top verified CVEs
SELECT v.cve, b.product, b.port, count(*) AS recs FROM vulns v JOIN banners b USING (rec_id)
WHERE v.verified AND v.cve IN ('CVE-2018-18441','CVE-2022-32548','CVE-2015-0204','CVE-2015-4000')
GROUP BY 1, 2, 3 QUALIFY row_number() OVER (PARTITION BY v.cve ORDER BY count(*) DESC) <= 2 ORDER BY 1, 4 DESC;
-- ransomware known flag vs catalog field
SELECT k.ransomware, count(DISTINCT v.cve) AS cves FROM vulns v JOIN kev k USING (cve) WHERE v.ransomware_campaign = 'Known' GROUP BY 1;
-- pubkey type vs sig alg
SELECT ssl_pubkey_type, count(*) AS recs, count(*) FILTER (WHERE ssl_sig_alg ILIKE 'ecdsa%') AS ecdsa_sig FROM banners WHERE has_ssl GROUP BY 1 ORDER BY 2 DESC LIMIT 6;
-- ssl versions notation sample
SELECT ssl_versions, count(*) AS recs FROM banners WHERE has_ssl GROUP BY 1 ORDER BY 2 DESC LIMIT 4;
-- rdp_encryption sample values
SELECT left(rdp_encryption, 200) AS rdp_enc, count(*) AS recs FROM banners WHERE rdp_encryption IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 3
;
-- top products behind the top 3 KEV CVEs
SELECT v.cve, b.product, count(*) AS recs FROM vulns v JOIN banners b USING (rec_id)
WHERE v.cve IN ('CVE-2023-44487','CVE-2024-38475','CVE-2021-40438') GROUP BY 1, 2
QUALIFY row_number() OVER (PARTITION BY v.cve ORDER BY count(*) DESC) <= 2 ORDER BY 1, 3 DESC;
-- catalog entries
SELECT cve, vendor, product, name, date_added, ransomware FROM kev WHERE cve IN ('CVE-2023-44487','CVE-2024-38475','CVE-2021-40438','CVE-2020-0796','CVE-2019-0708','CVE-2015-1635','CVE-2014-0160','CVE-2024-23897');
-- kev catalog size and ransomware split
SELECT count(*) AS entries, count(*) FILTER (WHERE ransomware = 'Known') AS ransomware_known FROM kev;
