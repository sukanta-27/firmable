-- 25 random attributed records per route, for a by-hand precision check
SELECT a.route, a.company_key, a.owner_class, a.bucket, left(a.org, 30) org, b.sni_hostname, left(b.ssl_subject_o, 25) cert_o,
       list_slice(b.domains, 1, 3) domains, left(b.http_title, 40) title, b.product, b.port
FROM read_parquet('archive/data/work/attr.parquet') a JOIN b USING (rec_id)
WHERE a.route IN ('domain', 'cert_o', 'org_rule', 'ntlm', 'sni') AND a.bucket IN ('other', 'cloud')
QUALIFY row_number() OVER (PARTITION BY a.route ORDER BY hash(a.rec_id)) <= 25
ORDER BY a.route, a.company_key;
