-- records, ips, time range
SELECT count(*) AS records, count(DISTINCT coalesce(ip_str, ipv6)) AS distinct_ips, count(ipv6) AS ipv6_records,
       min(ts) AS ts_min, max(ts) AS ts_max, count(*) - count(ts) AS ts_null FROM banners;
-- transport
SELECT transport, count(*) n FROM banners GROUP BY 1 ORDER BY 2 DESC;
-- top ports
SELECT port, count(*) n, round(100.0*count(*)/14608407,2) pct FROM banners GROUP BY 1 ORDER BY 2 DESC LIMIT 30;
-- top modules
SELECT module, count(*) n, round(100.0*count(*)/14608407,2) pct FROM banners GROUP BY 1 ORDER BY 2 DESC LIMIT 30;
-- countries
SELECT country_code, count(*) n, round(100.0*count(*)/14608407,2) pct FROM banners GROUP BY 1 ORDER BY 2 DESC LIMIT 25;
-- top orgs
SELECT org, count(*) n, round(100.0*count(*)/14608407,2) pct, count(DISTINCT ip_str) ips FROM banners GROUP BY 1 ORDER BY 2 DESC LIMIT 40;
-- tags
SELECT tag, count(*) n, round(100.0*count(*)/14608407,2) pct FROM (SELECT unnest(tags) tag FROM banners) GROUP BY 1 ORDER BY 2 DESC;
-- field presence
SELECT count_if(has_http) http, count_if(has_ssl) ssl, count_if(n_vulns>0) with_vulns, count(product) product, count(version) version,
       count(os) os, count_if(len(hostnames)>0) hostnames, count_if(len(domains)>0) domains, count(cloud_provider) cloud,
       count(sni_hostname) sni_hostname, count_if(len(proto_keys)>0) any_proto, count_if(has_screenshot) screenshot FROM banners;
-- cdn / cloud / honeypot
SELECT count_if(list_contains(tags,'cdn')) cdn, count_if(list_contains(tags,'cloud')) cloud,
       count_if(list_contains(tags,'cdn') OR list_contains(tags,'cloud')) cdn_or_cloud,
       count_if(list_contains(tags,'honeypot')) honeypot, count_if(org <> isp) org_ne_isp FROM banners;
-- top products
SELECT product, count(*) n FROM banners WHERE product IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 40;
-- cloud providers
SELECT cloud_provider, count(*) n FROM banners WHERE cloud_provider IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15;
-- http status
SELECT http_status, count(*) n FROM banners WHERE has_http GROUP BY 1 ORDER BY 2 DESC LIMIT 12;
-- waf
SELECT http_waf, count(*) n FROM banners WHERE http_waf IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 20;
-- protocol keys (authoritative census)
SELECT k, count(*) n FROM (SELECT unnest(proto_keys) k FROM banners) GROUP BY 1 ORDER BY 2 DESC;
