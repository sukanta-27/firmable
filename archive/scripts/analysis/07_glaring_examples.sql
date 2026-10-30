-- raw examples per candidate glaring signal (other+cloud), reproducible order
WITH ex AS (
  SELECT sig.signal, b.ip, b.port, left(b.org, 28) org, a.company_key, a.route, b.product, b.version,
         list_transform(list_filter(map_entries(b.vulns), lambda e: e.value.verified), lambda e: e.key) verified_cves,
         replace(left(b.data, 150), chr(10), ' ') banner, left(b.http_title, 30) title
  FROM s
  JOIN b USING (rec_id)
  JOIN read_parquet('archive/data/work/attr.parquet') a USING (rec_id)
  CROSS JOIN LATERAL (SELECT unnest(list_filter([
      CASE WHEN s.vuln_kev_verified THEN 'vuln_kev_verified' END,
      CASE WHEN s.heartbleed THEN 'heartbleed' END,
      CASE WHEN s.compromise THEN 'compromise' END,
      CASE WHEN s.db_no_auth THEN 'db_no_auth' END,
      CASE WHEN s.rdp_no_nla THEN 'rdp_no_nla' END,
      CASE WHEN s.smb_v1 THEN 'smb_v1' END,
      CASE WHEN s.smb_anonymous THEN 'smb_anonymous' END,
      CASE WHEN s.ftp_anonymous THEN 'ftp_anonymous' END,
      CASE WHEN s.ics THEN 'ics' END,
      CASE WHEN s.ai_infra THEN 'ai_infra' END,
      CASE WHEN s.oob_mgmt THEN 'oob_mgmt' END,
      CASE WHEN s.telnet THEN 'telnet' END,
      CASE WHEN s.open_dir THEN 'open_dir' END,
      CASE WHEN s.vnc THEN 'vnc' END,
      CASE WHEN s.medical_tag OR s.dicom_product THEN 'medical' END,
      CASE WHEN s.devops_exposed THEN 'devops_exposed' END
    ], lambda x: x IS NOT NULL)) AS signal) sig
  WHERE s.bucket IN ('other', 'cloud')
)
SELECT * FROM ex
QUALIFY row_number() OVER (PARTITION BY signal ORDER BY hash(ip || port::VARCHAR)) <= 7
ORDER BY signal, ip;
-- which products carry the verified KEV findings (other+cloud)
SELECT v.cve, coalesce(b.product, '(none)') product, b.port, count(*) recs, count(DISTINCT a.company_key) companies
FROM vulns v JOIN b USING (rec_id) JOIN read_parquet('archive/data/work/attr.parquet') a USING (rec_id)
WHERE v.verified AND v.kev AND b.bucket IN ('other', 'cloud')
GROUP BY 1, 2, 3 ORDER BY recs DESC LIMIT 20;
-- db_no_auth breakdown by store type
SELECT CASE WHEN mongodb LIKE '%"authentication":false%' THEN 'mongodb_noauth' WHEN redis IS NOT NULL THEN 'redis_open'
            WHEN elastic IS NOT NULL THEN 'elastic_open' WHEN rsync LIKE '%"authentication":false%' THEN 'rsync_noauth' END kind,
       count(*) recs, count(DISTINCT ip) ips, mode(org) top_org
FROM b WHERE bucket IN ('other', 'cloud') AND (mongodb LIKE '%"authentication":false%' OR redis IS NOT NULL OR elastic IS NOT NULL OR rsync LIKE '%"authentication":false%')
GROUP BY 1 ORDER BY 2 DESC;
-- ai_infra breakdown
SELECT k, count(*) recs, count(DISTINCT ip) ips, mode(bucket) top_bucket
FROM (SELECT bucket, ip, unnest(list_filter(proto_keys, lambda x: x IN ('mcp','ollama','llama_cpp','localai','comfyui','anything_llm','hermes_agent','gemini','chroma','milvus'))) k FROM b WHERE bucket IN ('other', 'cloud'))
GROUP BY 1 ORDER BY 2 DESC;
-- ollama: is the API open (models listed)?
SELECT count(*) recs, count(*) FILTER (WHERE ollama LIKE '%"models":[{%' OR ollama LIKE '%name%') with_models, left(mode(ollama), 200) sample FROM b WHERE ollama IS NOT NULL;
-- mcp: sample
SELECT left(mcp, 160) sample, count(*) n FROM b WHERE mcp IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 5;
-- compromise tags detail
SELECT tag, count(*) recs, count(DISTINCT ip) ips, mode(bucket) bucket, mode(product) product, mode(port) port
FROM (SELECT bucket, ip, product, port, unnest(tags) tag FROM b) WHERE tag IN ('c2', 'compromised', 'malware', 'doublepulsar', 'ssh-bad-key', 'tor', 'scanner')
GROUP BY 1 ORDER BY 2 DESC;
-- rdp without NLA: protocols distribution
SELECT json_extract_string(rdp_encryption, '$.protocols') protocols, count(*) recs FROM b WHERE rdp_encryption IS NOT NULL AND bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC LIMIT 8;
-- dicom probe: what products answer (other+cloud)
SELECT product, count(*) recs, mode(owner_class) owner FROM o WHERE module = 'dicom' AND bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC LIMIT 12;
-- vnc security types (other+cloud)
SELECT json_extract_string(vnc, '$.security_types') sec, count(*) recs FROM b WHERE vnc IS NOT NULL AND bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC LIMIT 8;
-- ics by owner class: hosting-hosted PLCs are suspected honeypots
SELECT owner_class, count(*) recs, count(DISTINCT ip) ips, count(*) FILTER (WHERE siemens_s7 IS NOT NULL) s7, count(*) FILTER (WHERE bacnet IS NOT NULL) bacnet,
       count(*) FILTER (WHERE list_contains(tags, 'ics')) ics_tag
FROM o WHERE bucket IN ('other', 'cloud') AND (siemens_s7 IS NOT NULL OR bacnet IS NOT NULL OR knx IS NOT NULL OR ethernetip IS NOT NULL
       OR codesys IS NOT NULL OR pcworx IS NOT NULL OR mitsubishi_q IS NOT NULL OR trane_tracer_sc IS NOT NULL OR list_contains(tags, 'ics'))
GROUP BY 1 ORDER BY 2 DESC;
-- ics protocol breakdown (other+cloud)
SELECT k, count(*) recs, count(DISTINCT ip) ips, mode(org) top_org, mode(country_code) cc
FROM (SELECT org, ip, country_code, unnest(list_filter(proto_keys, lambda x: x IN ('siemens_s7','bacnet','knx','ethernetip','codesys','pcworx','mitsubishi_q','trane_tracer_sc','pqube3_power_analyzers'))) k FROM b WHERE bucket IN ('other', 'cloud'))
GROUP BY 1 ORDER BY 2 DESC;
