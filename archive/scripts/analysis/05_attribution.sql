-- owner_class distribution, all records
SELECT owner_class, count(*) records, round(100.0*count(*)/14608407, 2) pct, count(DISTINCT ip) ips, count(DISTINCT org) orgs
FROM o GROUP BY 1 ORDER BY 2 DESC;
-- owner_class within bucket=other
SELECT owner_class, count(*) records, count(DISTINCT ip) ips, count(DISTINCT org) orgs,
       round(100.0*count(*) FILTER (WHERE org <> isp)/count(*)) pct_org_ne_isp
FROM o WHERE bucket = 'other' GROUP BY 1 ORDER BY 2 DESC;
-- infra domain sets
SELECT (SELECT count(*) FROM dom_stats WHERE ips >= 5 AND numeric_hosts >= 0.5 * hosts) rdns_domains,
       (SELECT count(*) FROM dom_lbl WHERE class <> 'company') labelled_infra,
       (SELECT count(*) FROM infra_dom) infra_domains_total;
-- build attribution table
CREATE TABLE attr AS
WITH cand AS (
  SELECT rec_id, sni_hostname, d, pos
  FROM (SELECT rec_id, sni_hostname, unnest(domains) AS d, generate_subscripts(domains, 1) AS pos FROM b)
  WHERE d LIKE '%.%' AND regexp_matches(d, '[a-z]')
    AND NOT regexp_matches(d, '(?i)(^|\.)(duckdns\.org|synology\.me|myds\.me|diskstation\.me|dsmynas\.(com|net)|myqnapcloud\.com|asuscomm\.com|asusrepeater\.com|asus\.com|draytek\.com|fortiddns\.com|ddns\.net|dyndns\.(org|biz|info)|hopto\.org|sytes\.net|zapto\.org|no-ip\.(com|org|biz|net|info)|noip\.me|myftp\.(org|biz)|servebeer\.com|chickenkiller\.com|mooo\.com|dynu\.(net|com)|dynv6\.net|dnsalias\.(com|net|org)|homeip\.net|sslip\.io|nip\.io|xip\.io|tplinkdns\.com|tplinker\.net|tplinkwifi\.net|routerlogin\.net|linksyssmartwifi\.com|remotewebaccess\.com|fritz\.box|home\.arpa|myfoscam\.org|dlinkddns\.com|mynetgear\.com|freeboxos\.fr|yunohost\.org|got-dns\.com|i234\.me|familyds\.(com|net)|myasustor\.com|dscloud\.me|loseyourip\.com|in-addr\.arpa|ip6\.arpa|localhost|localdomain|example\.(com|net|org)|test\.com|myvnc\.com|ngrok\.(io|app)|trycloudflare\.com|cloudfront\.net|amazonaws\.com|googleusercontent\.com|azurewebsites\.net|herokuapp\.com|akamai\.net|1e100\.net|fbcdn\.net|ytimg\.com|akamaiedge\.net|akamaitechnologies\.com|cloudflare\.net|incapdns\.net|online-server\.cloud|rack\.space|secureserver\.net)$')
    AND NOT regexp_matches(d, '\.(local|lan|home|internal|invalid|corp|intra)$')
    AND NOT regexp_matches(d, '(?i)^as\d+\.|^ip-\d+|host|cloud|server|vps|colo|cpanel|plesk|ptr|rdns|dyn|static|pool|telecom|telekom|broadband|fiber|fibra|wifi|wireless|cable|dsl|isp\b|provider|datacenter|dedicated|srv\.|-srv|srv\d')
),
cand2 AS (SELECT c.* FROM cand c ANTI JOIN infra_dom i ON c.d = i.domain),
kdom AS (SELECT rec_id, arg_min(d, pos) AS k_dom FROM cand2 GROUP BY 1),
ksni AS (SELECT rec_id, arg_min(d, pos) AS k_sni FROM cand2 WHERE sni_hostname IS NOT NULL AND ends_with(sni_hostname, d) GROUP BY 1),
kntlm_raw AS (
  SELECT rec_id, regexp_extract(lower(dn), '([^.]+\.(co|com|net|org|ac|gov|edu|or|ne|go)\.[a-z]{2}|[^.]+\.[^.]+)$', 1) AS k
  FROM (SELECT rec_id, json_extract_string(ntlm, '$.dns_domain_name') AS dn FROM b WHERE ntlm IS NOT NULL)
  WHERE dn LIKE '%.%' AND NOT regexp_matches(dn, '^\d+[-.]') AND NOT regexp_matches(dn, '\.(\d+|none|null|workgroup)$')
    AND NOT regexp_matches(dn, '(?i)(^|\.)(secureserver\.net|online-server\.cloud|rack\.space|contaboserver\.net|sl-reverse\.com|amazonaws\.com|cloudapp\.net|internal\.cloudapp\.net|vultr-guest|your-server\.de)$')
),
kntlm AS (
  SELECT r.rec_id,
         CASE WHEN regexp_matches(k, '\.(local|loc|lan|internal|corp|intra|home|domain|pri|priv|ad|int)$') THEN NULL ELSE k END AS k_ntlm,
         CASE WHEN regexp_matches(k, '\.(local|loc|lan|internal|corp|intra|home|domain|pri|priv|ad|int)$') THEN k END AS k_ntlm_ad
  FROM kntlm_raw r ANTI JOIN infra_dom i ON r.k = i.domain
),
x AS (
  SELECT o.rec_id, o.bucket, o.ip, o.org, o.owner_class, o.country_code,
    CASE WHEN o.owner_class IN ('enterprise', 'saas', 'edu', 'gov', 'secvendor') THEN o.org END AS k_org,
    ksni.k_sni,
    CASE WHEN o.ssl_subject_o IS NOT NULL AND (
           cl.class = 'company'
           OR (cl.class IS NULL
               AND length(o.ssl_subject_o) > 3
               AND NOT regexp_matches(o.ssl_subject_o, '(?i)^(none|n/?a|x+|unknown|default|test|example|localhost|self|my ?company|some ?organi[sz]ation|organi[sz]ation|company|companyname|ltd|llc|inc|corp|personal|private|home|internal|certificate|ssl|tls|router|camera|dvr|nvr|server|web|mail|admin|it|-+|\.+)( ?(ltd|llc|inc|co|corp)\.?)?$')
               AND NOT regexp_matches(o.ssl_subject_o, '(?i)self-?signed|default|webconfigurator|control panel|panel$|webserver on|webmin|^(fortinet|fortigate|sonicwall|draytek|synology|qnap|ubiquiti|mikrotik|cisco|huawei|zte|zyxel|netgear|tp-?link|d-?link|dahua|hikvision|axis|technicolor|sagemcom|arris|calix|plesk|cpanel|hestia|vesta|directadmin|fastpanel|bt-panel|aapanel|kubernetes|k3s|openshift|rancher|traefik|kong|istio|bitnami|mailcow|axigen|billionmail|zimbra|kerio|mdaemon|dptech|l7fw|mitrastar|vmware|proxmox|supermicro|super micro|dell|hp\b|hewlett|lenovo|ibm|oracle|microsoft|google|amazon|cloudflare|akamai|let.s encrypt|digicert|sectigo|comodo|godaddy|globalsign|entrust|zerossl|buypass|actalis|watchguard|sophos|stormshield|hillstone|sangfor|lancom|wildix|grandstream|yealink|avaya|polycom|ruckus|cambium|cradlepoint|sierra wireless|digi\b|lantronix|moxa|advantech|siemens|schneider|abb\b|honeywell|johnson controls|bosch|panasonic|sony|samsung|lg\b|philips|xiaomi|tuya|tuf-|rt-a|gt-a|zenwifi|teltonika|innovaphone|realtek|amcrest|raysharp|geneko|vimar|parallels|orgname|hikvision|uniview|reolink|foscam|avtech|geovision|vivotek|mobotix|axis)')))
         THEN o.ssl_subject_o END AS k_cert,
    kdom.k_dom,
    CASE WHEN o.owner_class = 'enterprise_h' THEN o.org END AS k_org_h,
    kntlm.k_ntlm, kntlm.k_ntlm_ad
  FROM o
  LEFT JOIN cert_lbl cl ON o.ssl_subject_o = cl.o
  LEFT JOIN kdom USING (rec_id)
  LEFT JOIN ksni USING (rec_id)
  LEFT JOIN kntlm USING (rec_id)
)
SELECT rec_id, bucket, ip, org, owner_class, country_code,
       lower(trim(coalesce(k_org, k_sni, k_cert, k_dom, k_org_h, k_ntlm, k_ntlm_ad))) AS company_key,
       CASE WHEN k_org IS NOT NULL THEN 'org_label' WHEN k_sni IS NOT NULL THEN 'sni' WHEN k_cert IS NOT NULL THEN 'cert_o'
            WHEN k_dom IS NOT NULL THEN 'domain' WHEN k_org_h IS NOT NULL THEN 'org_rule' WHEN k_ntlm IS NOT NULL THEN 'ntlm'
            WHEN k_ntlm_ad IS NOT NULL THEN 'ntlm_ad' END AS route,
       k_org, k_sni, k_cert, k_dom, k_org_h, k_ntlm, k_ntlm_ad
FROM x;
-- coverage by route
SELECT route, count(*) records, count(DISTINCT ip) ips, count(DISTINCT company_key) companies,
       count(*) FILTER (WHERE bucket = 'other') other, count(*) FILTER (WHERE bucket = 'cloud') cloud, count(*) FILTER (WHERE bucket = 'cdn') cdn, count(*) FILTER (WHERE bucket = 'honeypot') honeypot
FROM attr GROUP BY 1 ORDER BY 2 DESC;
-- attributable share by bucket
SELECT bucket, count(*) records, count(*) FILTER (WHERE company_key IS NOT NULL) attributed,
       round(100.0*count(*) FILTER (WHERE company_key IS NOT NULL)/count(*), 1) pct_records,
       count(DISTINCT ip) ips, count(DISTINCT CASE WHEN company_key IS NOT NULL THEN ip END) attributed_ips
FROM attr GROUP BY 1 ORDER BY 2 DESC;
-- attributable share by owner_class (other+cloud)
SELECT owner_class, count(*) records, round(100.0*count(*) FILTER (WHERE company_key IS NOT NULL)/count(*), 1) pct_attributed,
       count(DISTINCT company_key) companies, mode(route) top_route
FROM attr WHERE bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC;
-- companies by estate size (other+cloud)
WITH c AS (SELECT company_key, count(DISTINCT ip) ips, count(*) recs FROM attr WHERE company_key IS NOT NULL AND bucket IN ('other', 'cloud') GROUP BY 1)
SELECT count(*) companies, count(*) FILTER (WHERE ips = 1) one_ip, count(*) FILTER (WHERE ips BETWEEN 2 AND 5) ips_2_5, count(*) FILTER (WHERE ips BETWEEN 6 AND 50) ips_6_50,
       count(*) FILTER (WHERE ips > 50) ips_gt_50, sum(ips) total_ips, sum(recs) total_records FROM c;
-- largest companies by ips (other+cloud)
SELECT company_key, mode(route) route_mode, count(DISTINCT ip) ips, count(*) recs, mode(owner_class) owner_mode
FROM attr WHERE company_key IS NOT NULL AND bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY ips DESC LIMIT 40;
-- persist for later joins
COPY (SELECT * FROM attr) TO 'archive/data/work/attr.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
