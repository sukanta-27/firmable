-- top 300 domains (other+cloud) for labelling
SELECT dom, count(*) n, count(DISTINCT ip) ips, count(DISTINCT org) orgs, mode(org) top_org, mode(bucket) top_bucket
FROM (SELECT unnest(domains) dom, ip, org, bucket FROM b WHERE bucket IN ('other', 'cloud')) GROUP BY 1 ORDER BY 2 DESC LIMIT 300;
-- top 200 cert subject O (other+cloud)
SELECT ssl_subject_o, count(*) n, count(DISTINCT ip) ips, mode(org) top_org, mode(product) top_product
FROM b WHERE has_ssl AND bucket IN ('other', 'cloud') AND ssl_subject_o IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 200;
-- ips answering on more than 50 ports in bucket other: who are they
WITH p AS (SELECT ip, count(*) n, mode(org) org, count(DISTINCT port) ports FROM b WHERE bucket = 'other' GROUP BY 1 HAVING count(*) > 50)
SELECT org, count(*) ips, sum(n) records, round(avg(ports)) avg_ports FROM p GROUP BY 1 ORDER BY 2 DESC LIMIT 20;
-- records per ip by bucket
WITH p AS (SELECT bucket, ip, count(*) n FROM b GROUP BY 1, 2)
SELECT bucket, CASE WHEN n = 1 THEN '1' WHEN n <= 3 THEN '2-3' WHEN n <= 10 THEN '4-10' WHEN n <= 50 THEN '11-50' ELSE '>50' END recs_per_ip,
       count(*) ips, sum(n) records FROM p GROUP BY 1, 2 ORDER BY 1, 2;
-- sni hostnames: distinct hostnames and registrable domains (other+cloud)
SELECT bucket, count(*) recs, count(DISTINCT sni_hostname) hostnames, count(DISTINCT domains[1]) domains
FROM b WHERE sni_hostname IS NOT NULL AND bucket IN ('other', 'cloud') GROUP BY 1;
-- placeholder-looking org strings in bucket other
SELECT org, count(*) n, count(DISTINCT ip) ips FROM b
WHERE bucket = 'other' AND regexp_matches(org, '(?i)customer|pool|static|end user|dynamic|assigned|dhcp|subscriber|residential')
GROUP BY 1 ORDER BY 2 DESC LIMIT 30;
