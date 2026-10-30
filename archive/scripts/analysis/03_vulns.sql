-- vuln records by bucket: n_vulns distribution
SELECT bucket, count(*) recs, median(n_vulns) med, quantile_cont(n_vulns, 0.9) p90, max(n_vulns) mx, round(avg(n_vulns), 1) mean
FROM b WHERE n_vulns > 0 GROUP BY 1 ORDER BY 2 DESC;
-- top CVEs by records (other+cloud)
WITH v AS (SELECT v.*, b.product FROM vulns v JOIN b USING (rec_id) WHERE b.bucket IN ('other', 'cloud'))
SELECT cve, count(*) recs, count_if(verified) verified, max(kev) kev, round(max(cvss), 1) cvss, round(max(epss), 3) epss,
       max(ransomware_campaign) ransomware, mode(product) top_product, count(DISTINCT product) products
FROM v GROUP BY 1 ORDER BY 2 DESC LIMIT 30;
-- KEV-flagged CVEs (other+cloud): concentration by CVE
WITH v AS (SELECT v.*, b.product, b.version FROM vulns v JOIN b USING (rec_id) WHERE b.bucket IN ('other', 'cloud') AND v.kev)
SELECT cve, count(*) recs, count_if(verified) verified, round(max(cvss), 1) cvss, round(max(epss), 3) epss,
       max(ransomware_campaign) ransomware, mode(product) top_product, mode(version) top_version, count(DISTINCT product) products
FROM v GROUP BY 1 ORDER BY 2 DESC LIMIT 40;
-- KEV-flagged records by product (other+cloud)
WITH r AS (SELECT DISTINCT rec_id FROM vulns WHERE kev)
SELECT product, count(*) recs, count(DISTINCT version) versions FROM b JOIN r USING (rec_id) WHERE bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC LIMIT 25;
-- verified vulns: cve x product x bucket
SELECT v.cve, b.product, b.bucket, count(*) recs, round(max(v.cvss), 1) cvss, max(v.kev) kev, max(v.epss) epss
FROM vulns v JOIN b USING (rec_id) WHERE v.verified GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 40;
-- shodan kev flag vs CISA catalog over CVEs present in the data
WITH c AS (SELECT cve, max(kev) shodan_kev FROM vulns GROUP BY 1)
SELECT count(*) cves_in_data, count_if(shodan_kev) shodan_kev_true, count_if(k.cve IS NOT NULL) in_catalog,
       count_if(shodan_kev AND k.cve IS NULL) shodan_only, count_if(NOT coalesce(shodan_kev, false) AND k.cve IS NOT NULL) catalog_only
FROM c LEFT JOIN kev k USING (cve);
-- catalog-only CVEs (in KEV, Shodan flag missing), by records
WITH c AS (SELECT cve, max(kev) shodan_kev, count(*) recs FROM vulns GROUP BY 1)
SELECT c.cve, recs, k.vendor, k.product, k.date_added FROM c JOIN kev k USING (cve) WHERE NOT coalesce(shodan_kev, false) ORDER BY recs DESC LIMIT 20;
-- epss: shodan-embedded vs current FIRST feed, over distinct CVEs
WITH c AS (SELECT cve, max(epss) shodan_epss FROM vulns GROUP BY 1)
SELECT count(*) cves, count(e.cve) matched, round(corr(shodan_epss, e.epss), 3) corr_, round(avg(abs(shodan_epss - e.epss)), 4) mean_abs_diff,
       count_if(abs(shodan_epss - e.epss) > 0.1) diff_gt_0_1
FROM c JOIN epss e USING (cve);
-- identical vuln sets: top signatures (other+cloud)
WITH sig AS (SELECT rec_id, list_sort(map_keys(vulns)) cves FROM b WHERE n_vulns > 0 AND bucket IN ('other', 'cloud'))
SELECT md5(cves::VARCHAR) sig, len(cves) n_cves, count(*) recs, mode(product) top_product, mode(version) top_version, count(DISTINCT version) versions
FROM sig JOIN b USING (rec_id) GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15;
-- vulns per product (other+cloud)
SELECT product, count(*) recs, round(avg(n_vulns), 1) mean_vulns, median(n_vulns) med, count(DISTINCT version) versions,
       count_if(len(list_filter(map_values(vulns), lambda v: v.kev)) > 0) kev_recs,
       count_if(len(list_filter(map_values(vulns), lambda v: v.verified)) > 0) verified_recs
FROM b WHERE n_vulns > 0 AND bucket IN ('other', 'cloud') GROUP BY 1 ORDER BY 2 DESC LIMIT 20;
