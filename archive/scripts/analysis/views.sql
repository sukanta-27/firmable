-- Shared views loaded by q.py before every query file.

-- b: banners plus the coarse owner bucket used to separate CDN/cloud/honeypot noise.
CREATE VIEW b AS
SELECT *,
       CASE WHEN list_contains(tags, 'honeypot') THEN 'honeypot'
            WHEN list_contains(tags, 'cdn')      THEN 'cdn'
            WHEN list_contains(tags, 'cloud')    THEN 'cloud'
            ELSE 'other' END AS bucket,
       coalesce(ip_str, ipv6) AS ip
FROM banners;

-- Hand labels. Org labels match on the first 48 characters because the labelling
-- sheet truncated long names there.
CREATE TABLE org_lbl  AS SELECT DISTINCT left(org, 48) AS k, class FROM read_csv('reference/labels/org_class.csv', header=true);
CREATE TABLE dom_lbl  AS SELECT domain, class FROM read_csv('reference/labels/domain_class.csv', header=true);
CREATE TABLE cert_lbl AS SELECT o, class FROM read_csv('reference/labels/cert_o_class.csv', header=true);

-- CISA Known Exploited Vulnerabilities catalog (data/external/kev.json).
CREATE VIEW kev AS
SELECT v.cveID AS cve, v.vendorProject AS vendor, v.product, v.vulnerabilityName AS name,
       v.dateAdded::DATE AS date_added, v.dueDate::DATE AS due_date,
       v.knownRansomwareCampaignUse AS ransomware, v.shortDescription AS description
FROM (SELECT unnest(vulnerabilities) AS v
      FROM read_json('data/external/kev.json', maximum_object_size=104857600));

-- FIRST EPSS daily scores (data/external/epss_scores-current.csv.gz). First line is a comment.
CREATE VIEW epss AS
SELECT cve, epss::DOUBLE AS epss, percentile::DOUBLE AS percentile
FROM read_csv('data/external/epss_scores-current.csv.gz', skip=1, header=true);

-- owner_class: who owns the IP. Tags first, then hand labels, then keyword rules for
-- the long tail. 'enterprise_h' marks the rule-based default so its precision can be
-- measured separately from hand-labelled enterprises.
CREATE VIEW o AS
SELECT b.*,
  coalesce(
    CASE WHEN bucket = 'honeypot' THEN 'honeypot' WHEN bucket = 'cdn' THEN 'cdn' END,
    ol.class,
    CASE WHEN bucket = 'cloud' THEN 'hosting' END,
    CASE
      WHEN org IS NULL OR org = '' THEN 'placeholder'
      WHEN regexp_matches(org, '(?i)customer|pool|static ip|dynamic|assigned|dhcp|subscriber|residential|end user|unassign|address (block|space|range)|ip (block|space|range)|allocat|infrastructure|^company [0-9a-f]{8}') THEN 'placeholder'
      WHEN regexp_matches(org, '(?i)\bcdn\b|akamai|cloudflare|fastly|incapsula|imperva|edgecast|limelight|cachefly|bunny ?cdn|ddos-guard|stackpath|edgio|cdnetworks') THEN 'cdn'
      WHEN regexp_matches(org, '(?i)hosting|hoster|host\b|server|cloud|data ?cent|datacenter|\bcolo\b|colocation|\bvps\b|dedicated|idc\b|web ?services|internet services|digitalocean|linode|vultr|hetzner|\bovh\b|contabo|ionos|godaddy|namecheap|leaseweb|scaleway|rackspace|dreamhost|hostinger|hostgator|bluehost|siteground|kamatera|upcloud|zenlayer|choopa|psychz|quadranet|m247|worldstream') THEN 'hosting'
      WHEN regexp_matches(org, '(?i)telecom|telekom|telefon|telco|communications?|broadband|breiband|bredband|breedband|banda larga|\bcable\b|cable ?tv|television|fib(er|re)|wireless|cellular|\binternet\b|network|\bnet\b|online|\bdsl\b|\badsl\b|unicom|chinanet|china mobile|vodafone|\borange\b|t-mobile|comcast|charter|verizon|at&t|\bkpn\b|telia|telenor|telstra|optus|rogers|videotron|telus|cogeco|spectrum|frontier|centurylink|lumen|windstream|altice|claro|movistar|rostelecom|turkcell|etisalat|ooredoo|airtel|\bjio\b|bsnl|vnpt|viettel|pldt|singtel|starhub|telkom|maxis|celcom|chunghwa|hinet|pccw|hkbn|\bhgc\b|softbank|kddi|biglobe|so-net|\bntt\b|\bisp\b|\bwisp\b|net\b|tel\b|lan\b|link\b|com\b|surf|planet|kabel|cabo|optic|optik') THEN 'isp'
      WHEN regexp_matches(org, '(?i)universit|college|school|institute of tech|polytechnic|academ|education|\.edu|research (council|center|centre|network)|hochschule|universidad|universidade|université|universität') THEN 'edu'
      WHEN regexp_matches(org, '(?i)government|ministry|ministerio|minist[eè]re|municipal|city of|county|state of|federal|\bgov\b|department of|agency|authority|council|prefecture|gemeente|kommun|ayuntamiento|bundes|landes|comune di|mairie') THEN 'gov'
      ELSE 'enterprise_h' END) AS owner_class
FROM b LEFT JOIN org_lbl ol ON left(b.org, 48) = ol.k;

-- Reverse-DNS detector: a domain whose hostnames are mostly numeric belongs to an
-- ISP or hoster whatever its name looks like (e.g. 179-125-1-1.embratel.net.br).
CREATE TABLE dom_stats AS
SELECT d AS domain, count(*) AS hosts, count(DISTINCT ip) AS ips,
       count_if(regexp_matches(h, '\d{1,3}[-.]\d{1,3}[-.]\d{1,3}')) AS numeric_hosts
FROM (SELECT ip, unnest(domains) AS d, hostnames FROM b WHERE bucket IN ('other', 'cloud')),
     UNNEST(list_filter(hostnames, lambda x: x = d OR ends_with(x, '.' || d))) AS t(h)
GROUP BY 1;

-- Domains that never identify a customer: hand-labelled infrastructure, reverse-DNS
-- domains, and the dominant domain of any ISP/hoster/placeholder org.
CREATE TABLE infra_dom AS
SELECT domain FROM dom_stats WHERE ips >= 5 AND numeric_hosts >= 0.5 * hosts
UNION
SELECT domain FROM dom_lbl WHERE class <> 'company'
UNION
SELECT d FROM (
  SELECT org, d, count(*) AS n, count(*) * 1.0 / sum(count(*)) OVER (PARTITION BY org) AS share
  FROM (SELECT org, unnest(domains) AS d FROM o
        WHERE bucket IN ('other', 'cloud') AND owner_class IN ('isp', 'hosting', 'placeholder', 'cdn', 'proxy', 'vpn'))
  GROUP BY 1, 2
) WHERE n >= 50 AND share >= 0.3;

-- s: one boolean per candidate signal, per record. Definitions live here so every
-- later query counts the same thing.
CREATE VIEW s AS
SELECT rec_id, bucket, owner_class, ip, org, isp, product, version, port, transport, country_code, module,
  n_vulns > 0                                                                        AS vuln_any,
  len(list_filter(map_values(vulns), lambda v: v.verified)) > 0                      AS vuln_verified,
  len(list_filter(map_values(vulns), lambda v: v.kev)) > 0                           AS vuln_kev,
  len(list_filter(map_values(vulns), lambda v: v.kev AND v.verified)) > 0            AS vuln_kev_verified,
  len(list_filter(map_values(vulns), lambda v: v.ransomware_campaign = 'Known')) > 0 AS vuln_ransomware,
  len(list_filter(map_values(vulns), lambda v: v.cvss >= 9)) > 0                     AS vuln_cvss9,
  len(list_filter(map_values(vulns), lambda v: v.epss >= 0.5)) > 0                   AS vuln_epss50,
  list_contains(tags, 'eol-product')                                                 AS eol_product,
  list_contains(tags, 'eol-os')                                                      AS eol_os,
  coalesce(ssl_expired, false)                                                       AS cert_expired,
  list_contains(tags, 'self-signed')                                                 AS cert_self_signed,
  list_has_any(ssl_versions, ['TLSv1', 'TLSv1.1'])                                   AS tls_1_0_1_1,
  list_has_any(ssl_versions, ['SSLv2', 'SSLv3'])                                     AS ssl_v2_v3,
  len(list_filter(ssl_ciphers, lambda c: regexp_matches(c, 'RC4|DES|EXPORT|NULL|MD5'))) > 0 AS weak_cipher,
  ssl_pubkey_type = 'rsa' AND ssl_pubkey_bits < 2048                                 AS rsa_lt_2048,
  ssl_sig_alg ILIKE '%sha1%'                                                         AS cert_sha1,
  ssl_dh_bits < 2048                                                                 AS dh_lt_2048,
  opts_heartbleed ILIKE '%VULNERABLE%'                                               AS heartbleed,
  product = 'Remote Desktop Protocol' OR rdp_encryption IS NOT NULL                  AS rdp,
  rdp_encryption IS NOT NULL AND rdp_encryption NOT LIKE '%CredSSP%'                 AS rdp_no_nla,
  vnc IS NOT NULL OR product = 'VNC'                                                 AS vnc,
  telnet IS NOT NULL AND (port IN (23, 2323) OR regexp_matches(data, '(?i)login:|password:|user access verification|username:')) AS telnet,
  vnc IS NOT NULL AND (vnc LIKE '%"None"%' OR data LIKE '%1: None%')                 AS vnc_noauth,
  list_has_any(ssh_kex_algorithms, ['diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1'])
    OR list_has_any(ssh_encryption_algorithms, ['3des-cbc','arcfour','arcfour128','arcfour256','blowfish-cbc']) AS ssh_weak_algos,
  list_contains(tags, 'ssh-bad-key')                                                 AS ssh_bad_key,
  smb IS NOT NULL                                                                    AS smb,
  smb LIKE '%"smb_version":1%'                                                       AS smb_v1,
  smb LIKE '%"anonymous":true%'                                                      AS smb_anonymous,
  ftp IS NOT NULL                                                                    AS ftp,
  ftp LIKE '%"anonymous":true%'                                                      AS ftp_anonymous,
  list_contains(tags, 'database') OR mysql IS NOT NULL OR mysqlx IS NOT NULL OR mongodb IS NOT NULL OR redis IS NOT NULL
    OR elastic IS NOT NULL OR clickhouse IS NOT NULL OR influxdb IS NOT NULL OR couchdb IS NOT NULL OR oracle_tnslsnr IS NOT NULL
    OR mssql_ssrp IS NOT NULL OR pgbouncer IS NOT NULL OR neo4j_browser IS NOT NULL OR cassandra IS NOT NULL
    OR couchbase_server IS NOT NULL OR questdb IS NOT NULL OR tidb IS NOT NULL OR ibm_db2 IS NOT NULL   AS db_exposed,
  mongodb LIKE '%"authentication":false%' OR (redis IS NOT NULL AND data LIKE '%redis_version%') OR elastic IS NOT NULL
    OR (rsync LIKE '%"authentication":false%' AND rsync NOT LIKE '%"modules":{}%')                 AS db_no_auth,
  kubernetes IS NOT NULL OR docker_registry IS NOT NULL OR etcd IS NOT NULL OR consul IS NOT NULL OR vault IS NOT NULL
    OR list_contains(tags, 'devops')                                                 AS devops_exposed,
  node_exporter IS NOT NULL OR windows_exporter IS NOT NULL OR netdata IS NOT NULL OR ganglia IS NOT NULL OR superset IS NOT NULL AS metrics_exposed,
  isakmp IS NOT NULL OR pptp IS NOT NULL OR l2tp IS NOT NULL OR fortinet IS NOT NULL OR checkpoint IS NOT NULL OR sonicwall IS NOT NULL
    OR cisco_anyconnect IS NOT NULL OR draytek_vigor IS NOT NULL OR list_contains(tags, 'vpn')  AS vpn_edge,
  fortinet IS NOT NULL OR checkpoint IS NOT NULL OR sonicwall IS NOT NULL OR cisco_anyconnect IS NOT NULL OR draytek_vigor IS NOT NULL
    OR product ILIKE '%fortinet%' OR product ILIKE '%fortigate%' OR product ILIKE '%sonicwall%' OR product ILIKE '%palo alto%'
    OR product ILIKE '%pulse%' OR product ILIKE '%ivanti%' OR product ILIKE '%citrix%' OR product ILIKE '%netscaler%'
    OR product ILIKE '%checkpoint%' OR product ILIKE '%check point%' OR product ILIKE '%draytek%' OR product ILIKE '%bigip%' AS named_edge_appliance,
  hp_ilo IS NOT NULL OR ipmi IS NOT NULL OR vmware IS NOT NULL                       AS oob_mgmt,
  mikrotik_winbox IS NOT NULL OR mikrotik_routeros IS NOT NULL OR milesight_routers IS NOT NULL OR gl_inet IS NOT NULL
    OR ubiquiti IS NOT NULL OR netgear IS NOT NULL OR dd_wrt IS NOT NULL OR huawei_home_gateway IS NOT NULL
    OR tilginAB_home_gateway IS NOT NULL OR product ILIKE '%TR-069%' OR product ILIKE 'MikroTik%'      AS router_mgmt,
  hikvision IS NOT NULL OR dahua IS NOT NULL OR dahua_dvr_web IS NOT NULL OR ip_camera IS NOT NULL OR reolink_baichuan IS NOT NULL
    OR product ILIKE '%camera%' OR product ILIKE '%dvr%' OR product ILIKE '%nvr%'     AS cameras_dvr,
  synology_dsm IS NOT NULL OR synology_srm IS NOT NULL OR qnap IS NOT NULL OR afp IS NOT NULL OR iscsi IS NOT NULL OR ndmp IS NOT NULL OR dav IS NOT NULL AS nas_storage,
  hp_printer_embedded_web_server IS NOT NULL OR kyocera_printer_panel IS NOT NULL OR samsung_syncthru_web_service IS NOT NULL
    OR ipp_cups IS NOT NULL OR (module = 'printer-job-language' AND product IS NOT NULL)  AS printers,
  siemens_s7 IS NOT NULL OR bacnet IS NOT NULL OR knx IS NOT NULL OR ethernetip IS NOT NULL OR codesys IS NOT NULL OR pcworx IS NOT NULL
    OR mitsubishi_q IS NOT NULL OR trane_tracer_sc IS NOT NULL OR pqube3_power_analyzers IS NOT NULL OR list_contains(tags, 'ics') AS ics,
  list_contains(tags, 'medical')                                                     AS medical_tag,
  product ILIKE '%dicom%' OR product ILIKE '%pacs%' OR product ILIKE '%orthanc%' OR product ILIKE '%dcm4che%' OR product ILIKE '%conquest%' AS dicom_product,
  mcp IS NOT NULL OR ollama IS NOT NULL OR llama_cpp IS NOT NULL OR localai IS NOT NULL OR comfyui IS NOT NULL OR anything_llm IS NOT NULL
    OR hermes_agent IS NOT NULL OR gemini IS NOT NULL OR chroma IS NOT NULL OR milvus IS NOT NULL
    OR list_contains(tags, 'ai') OR list_contains(tags, 'mcp')                        AS ai_infra,
  list_contains(tags, 'c2') OR list_contains(tags, 'compromised') OR list_contains(tags, 'malware')
    OR list_contains(tags, 'doublepulsar') OR cobalt_strike_beacon IS NOT NULL        AS compromise,
  list_contains(tags, 'proxy')                                                       AS proxy_tag,
  list_contains(tags, 'tor')                                                         AS tor_tag,
  list_contains(tags, 'scanner')                                                     AS scanner_tag,
  open_dir IS NOT NULL OR list_contains(tags, 'open-dir')                            AS open_dir,
  regexp_matches(http_title, '(?i)^(IIS Windows( Server)?|Apache2 (Ubuntu|Debian) Default Page.*|Welcome to nginx!?|Test Page for the (Apache|Nginx) HTTP Server.*|Welcome to CentOS|Apache HTTP Server Test Page.*|Welcome to tengine!?|Welcome to OpenResty!?|It works!?)$') AS web_default_page,
  http_title ILIKE 'Index of /%'                                                     AS web_index_of,
  regexp_matches(http_title, '(?i)hacked by|defaced|pwned by|owned by')              AS web_defaced,
  regexp_matches(http_title, '(?i)phpmyadmin|grafana|jenkins|kibana|zabbix|webmin|cpanel|plesk|roundcube|adminer') AS web_admin_panel,
  http_status = 200                                                                  AS http_200,
  http_status = 200 AND http_headers ILIKE '%"strict-transport-security"%'           AS web_hsts,
  http_status = 200 AND http_headers ILIKE '%"content-security-policy"%'             AS web_csp,
  http_securitytxt IS NOT NULL                                                       AS securitytxt,
  http_waf IS NOT NULL                                                               AS waf,
  list_contains(tags, 'pqc')                                                         AS pqc,
  has_ssl, has_http
FROM o;
