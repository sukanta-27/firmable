-- bucket sizes
SELECT bucket, count(*) n, round(100.0*count(*)/14608407,2) pct, count(DISTINCT ip) ips FROM b GROUP BY 1 ORDER BY 2 DESC;
-- rec_id uniqueness
SELECT count(DISTINCT rec_id) distinct_rec_ids, count(*) rows_ FROM b;
-- org coverage curve, all records
WITH o AS (SELECT org, count(*) n FROM b GROUP BY 1),
     r AS (SELECT n, sum(n) OVER (ORDER BY n DESC ROWS UNBOUNDED PRECEDING) cum, row_number() OVER (ORDER BY n DESC) rk FROM o)
SELECT (SELECT count(*) FROM o) distinct_orgs,
       round(100.0*max(CASE WHEN rk=100 THEN cum END)/14608407,1) top100_pct,
       round(100.0*max(CASE WHEN rk=500 THEN cum END)/14608407,1) top500_pct,
       round(100.0*max(CASE WHEN rk=1000 THEN cum END)/14608407,1) top1000_pct,
       round(100.0*max(CASE WHEN rk=5000 THEN cum END)/14608407,1) top5000_pct FROM r;
-- org coverage curve, bucket=other
WITH o AS (SELECT org, count(*) n FROM b WHERE bucket='other' GROUP BY 1),
     t AS (SELECT sum(n) tot FROM o),
     r AS (SELECT n, sum(n) OVER (ORDER BY n DESC ROWS UNBOUNDED PRECEDING) cum, row_number() OVER (ORDER BY n DESC) rk FROM o)
SELECT (SELECT count(*) FROM o) distinct_orgs, (SELECT tot FROM t) records,
       round(100.0*max(CASE WHEN rk=100 THEN cum END)/(SELECT tot FROM t),1) top100_pct,
       round(100.0*max(CASE WHEN rk=500 THEN cum END)/(SELECT tot FROM t),1) top500_pct,
       round(100.0*max(CASE WHEN rk=1000 THEN cum END)/(SELECT tot FROM t),1) top1000_pct,
       round(100.0*max(CASE WHEN rk=5000 THEN cum END)/(SELECT tot FROM t),1) top5000_pct FROM r;
-- org vs isp in bucket=other
SELECT org = isp AS org_equals_isp, count(*) n, count(DISTINCT org) orgs FROM b WHERE bucket='other' GROUP BY 1;
-- top isp when org differs from isp (bucket=other)
SELECT isp, count(*) n, count(DISTINCT org) orgs FROM b WHERE bucket='other' AND org <> isp GROUP BY 1 ORDER BY 2 DESC LIMIT 25;
-- domain coverage, bucket=other
WITH d AS (SELECT unnest(domains) dom FROM b WHERE bucket='other'), o AS (SELECT dom, count(*) n FROM d GROUP BY 1),
     t AS (SELECT sum(n) tot FROM o),
     r AS (SELECT n, sum(n) OVER (ORDER BY n DESC ROWS UNBOUNDED PRECEDING) cum, row_number() OVER (ORDER BY n DESC) rk FROM o)
SELECT (SELECT count(*) FROM o) distinct_domains, (SELECT tot FROM t) domain_mentions,
       round(100.0*max(CASE WHEN rk=100 THEN cum END)/(SELECT tot FROM t),1) top100_pct,
       round(100.0*max(CASE WHEN rk=500 THEN cum END)/(SELECT tot FROM t),1) top500_pct,
       round(100.0*max(CASE WHEN rk=2000 THEN cum END)/(SELECT tot FROM t),1) top2000_pct FROM r;
-- top domains in bucket=other
SELECT dom, count(*) n, count(DISTINCT ip) ips, count(DISTINCT org) orgs, mode(org) top_org
FROM (SELECT unnest(domains) dom, ip, org FROM b WHERE bucket='other') GROUP BY 1 ORDER BY 2 DESC LIMIT 80;
-- domains by number of ips (bucket=other)
WITH d AS (SELECT dom, count(DISTINCT ip) ips FROM (SELECT unnest(domains) dom, ip FROM b WHERE bucket='other') GROUP BY 1)
SELECT CASE WHEN ips=1 THEN '1' WHEN ips<=5 THEN '2-5' WHEN ips<=50 THEN '6-50' WHEN ips<=1000 THEN '51-1000' ELSE '>1000' END ips_per_domain,
       count(*) domains, sum(ips) ips FROM d GROUP BY 1 ORDER BY 1;
-- cert subject O coverage (bucket other+cloud)
SELECT count(*) ssl_records, count(ssl_subject_o) with_o, count(DISTINCT ssl_subject_o) distinct_o FROM b WHERE has_ssl AND bucket IN ('other','cloud');
-- top cert subject O (bucket other+cloud)
SELECT ssl_subject_o, count(*) n, count(DISTINCT ip) ips, mode(org) top_org FROM b WHERE has_ssl AND bucket IN ('other','cloud') AND ssl_subject_o IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 50;
-- ntlm dns domain names
SELECT json_extract_string(ntlm,'$.dns_domain_name') dns_domain, count(*) n FROM b WHERE ntlm IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 25;
-- ntlm: dotted AD domain vs standalone machine, by bucket
SELECT bucket, count(*) n,
       count_if(json_extract_string(ntlm,'$.dns_domain_name') LIKE '%.%') dotted_domain,
       count_if(json_extract_string(ntlm,'$.dns_domain_name') = json_extract_string(ntlm,'$.netbios_computer_name')) standalone
FROM b WHERE ntlm IS NOT NULL GROUP BY 1 ORDER BY 2 DESC;
-- sni hostname by bucket
SELECT bucket, count(*) n, count(sni_hostname) with_sni FROM b GROUP BY 1 ORDER BY 2 DESC;
-- records per ip
WITH p AS (SELECT ip, count(*) n FROM b GROUP BY 1)
SELECT CASE WHEN n=1 THEN '1' WHEN n<=3 THEN '2-3' WHEN n<=10 THEN '4-10' WHEN n<=50 THEN '11-50' ELSE '>50' END records_per_ip,
       count(*) ips, sum(n) records FROM p GROUP BY 1 ORDER BY 1;
