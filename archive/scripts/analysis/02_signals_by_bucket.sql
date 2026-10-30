-- signal prevalence by owner bucket (records), definitions from the shared view s
WITH agg AS (
  SELECT bucket, count(*) AS total,
    count(*) FILTER (WHERE vuln_any) vuln_any, count(*) FILTER (WHERE vuln_verified) vuln_verified, count(*) FILTER (WHERE vuln_kev) vuln_kev,
    count(*) FILTER (WHERE vuln_kev_verified) vuln_kev_verified, count(*) FILTER (WHERE vuln_ransomware) vuln_ransomware,
    count(*) FILTER (WHERE vuln_cvss9) vuln_cvss9, count(*) FILTER (WHERE vuln_epss50) vuln_epss50,
    count(*) FILTER (WHERE eol_product) eol_product, count(*) FILTER (WHERE eol_os) eol_os, count(*) FILTER (WHERE cert_expired) cert_expired,
    count(*) FILTER (WHERE cert_self_signed) cert_self_signed, count(*) FILTER (WHERE tls_1_0_1_1) tls_1_0_1_1, count(*) FILTER (WHERE ssl_v2_v3) ssl_v2_v3,
    count(*) FILTER (WHERE weak_cipher) weak_cipher, count(*) FILTER (WHERE rsa_lt_2048) rsa_lt_2048, count(*) FILTER (WHERE cert_sha1) cert_sha1,
    count(*) FILTER (WHERE dh_lt_2048) dh_lt_2048, count(*) FILTER (WHERE heartbleed) heartbleed, count(*) FILTER (WHERE rdp) rdp,
    count(*) FILTER (WHERE rdp_no_nla) rdp_no_nla, count(*) FILTER (WHERE vnc) vnc, count(*) FILTER (WHERE vnc_noauth) vnc_noauth,
    count(*) FILTER (WHERE telnet) telnet, count(*) FILTER (WHERE ssh_weak_algos) ssh_weak_algos, count(*) FILTER (WHERE ssh_bad_key) ssh_bad_key,
    count(*) FILTER (WHERE smb) smb, count(*) FILTER (WHERE smb_v1) smb_v1, count(*) FILTER (WHERE smb_anonymous) smb_anonymous,
    count(*) FILTER (WHERE ftp) ftp, count(*) FILTER (WHERE ftp_anonymous) ftp_anonymous, count(*) FILTER (WHERE db_exposed) db_exposed,
    count(*) FILTER (WHERE db_no_auth) db_no_auth, count(*) FILTER (WHERE devops_exposed) devops_exposed, count(*) FILTER (WHERE metrics_exposed) metrics_exposed,
    count(*) FILTER (WHERE vpn_edge) vpn_edge, count(*) FILTER (WHERE named_edge_appliance) named_edge_appliance, count(*) FILTER (WHERE oob_mgmt) oob_mgmt,
    count(*) FILTER (WHERE router_mgmt) router_mgmt, count(*) FILTER (WHERE cameras_dvr) cameras_dvr, count(*) FILTER (WHERE nas_storage) nas_storage,
    count(*) FILTER (WHERE printers) printers, count(*) FILTER (WHERE ics) ics,
    count(*) FILTER (WHERE ics AND owner_class NOT IN ('hosting', 'cdn', 'proxy', 'vpn')) ics_real,
    count(*) FILTER (WHERE medical_tag) medical_tag, count(*) FILTER (WHERE dicom_product) dicom_product, count(*) FILTER (WHERE ai_infra) ai_infra,
    count(*) FILTER (WHERE compromise) compromise, count(*) FILTER (WHERE proxy_tag) proxy_tag, count(*) FILTER (WHERE tor_tag) tor_tag,
    count(*) FILTER (WHERE scanner_tag) scanner_tag, count(*) FILTER (WHERE open_dir) open_dir, count(*) FILTER (WHERE web_default_page) web_default_page,
    count(*) FILTER (WHERE web_index_of) web_index_of, count(*) FILTER (WHERE web_defaced) web_defaced, count(*) FILTER (WHERE web_admin_panel) web_admin_panel,
    count(*) FILTER (WHERE http_200) http_200, count(*) FILTER (WHERE web_hsts) web_hsts, count(*) FILTER (WHERE web_csp) web_csp,
    count(*) FILTER (WHERE securitytxt) securitytxt, count(*) FILTER (WHERE waf) waf, count(*) FILTER (WHERE pqc) pqc,
    count(*) FILTER (WHERE has_ssl) has_ssl, count(*) FILTER (WHERE has_http) has_http
  FROM s GROUP BY bucket
),
long AS (
  SELECT bucket, name AS signal, value AS n
  FROM (UNPIVOT agg ON COLUMNS(* EXCLUDE (bucket)) INTO NAME name VALUE value)
)
SELECT signal,
       sum(CASE WHEN bucket = 'other'    THEN n END) AS other,
       sum(CASE WHEN bucket = 'cloud'    THEN n END) AS cloud,
       sum(CASE WHEN bucket = 'cdn'      THEN n END) AS cdn,
       sum(CASE WHEN bucket = 'honeypot' THEN n END) AS honeypot,
       sum(n) AS all_records
FROM long GROUP BY 1 ORDER BY other DESC;
