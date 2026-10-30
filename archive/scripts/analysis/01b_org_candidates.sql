-- top 600 orgs outside cdn/cloud/honeypot, with context for hand labelling
SELECT org, count(*) n, count(DISTINCT ip) ips,
       round(100.0*count_if(org <> isp)/count(*)) pct_org_ne_isp,
       mode(country_code) cc, mode(isp) top_isp,
       list_slice(list_distinct(list(d) FILTER (WHERE d IS NOT NULL)), 1, 4) sample_domains,
       list_slice(list_distinct(list(product) FILTER (WHERE product IS NOT NULL)), 1, 4) sample_products
FROM (SELECT org, ip, isp, country_code, product, domains[1] d FROM b WHERE bucket = 'other')
GROUP BY 1 ORDER BY 2 DESC LIMIT 600;
