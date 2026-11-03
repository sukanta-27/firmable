"""Steps 2-3 and 5. Every candidate signal as SQL on bronze, with its prevalence,
concentration, tag carriers, attributable share, and 10 records to read.

Each signal is a WHERE predicate on `banner` (temp table `verified` holds rec_ids with a
verified CVE). Output: out/signals/<name>.<dataset>.txt, one file per signal.
Run: uv run python archive/blind-analysis/scripts/04_signals.py sample|full [name ...]
Needs cache/ip_stats.<dataset>.parquet from 00_ip_stats.py.
"""

import sys

from _db import ROOT, connect, show

HERE = ROOT / "archive" / "blind-analysis"

OPTS_VULNS = "json_extract_string(opts, '$.vulns[*]')"
PROTO = "coalesce(product, '') || ' ' || coalesce(version, '')"


SHOT_LABELS = "extra['screenshot.labels']"
SHOT_TEXT = "extra['screenshot.text']"


def j(obj: str, n: int = 300) -> str:
    return f"left(CAST({obj} AS VARCHAR), {n})"


def json_extract(obj: str, path: str) -> str:
    return f"json_extract({obj}, '{path}')"


# name: (predicate, evidence expression, proof type)
SIGNALS: dict[str, tuple[str, str, str]] = {
    # Scanner tests
    "vuln_verified": (
        "rec_id IN (SELECT rec_id FROM verified)",
        f"(SELECT string_agg(cve, ',') FROM vuln v WHERE v.rec_id = m.rec_id AND verified)"
        f" || ' | opts.vulns=' || {j(OPTS_VULNS, 80)} || ' | ' || left(data, 160)",
        "scanner test",
    ),
    "heartbleed_vulnerable": (
        "json_extract_string(opts, '$.heartbleed') LIKE '% - VULNERABLE%'",
        "left(json_extract_string(opts, '$.heartbleed'), 200)",
        "scanner test",
    ),
    "bluekeep_verified": (
        "rec_id IN (SELECT rec_id FROM vuln WHERE verified AND cve = 'CVE-2019-0708')",
        f"{j('rdp_encryption', 200)} || ' | ' || left(data, 120)",
        "scanner test",
    ),
    "ghostcat_opts_only": (
        f"list_contains({OPTS_VULNS}, 'CVE-2020-1938')",
        f"{j(OPTS_VULNS, 80)} || ' | ' || left(data, 200)",
        "scanner test",
    ),
    "opts_vuln_tilde": (
        f"len(list_filter({OPTS_VULNS}, lambda x: x LIKE '~%')) > 0",
        f"{j(OPTS_VULNS, 120)} || ' | ' || coalesce(http_title, '') || ' | ' || left(data, 120)",
        "scanner test",
    ),
    # Scanner tags
    "tag_compromised": (
        "list_contains(tags, 'compromised')",
        "array_to_string(tags, ',') || ' | ' || coalesce(http_title, '') || ' | '"
        " || left(data, 220)",
        "tag",
    ),
    "tag_c2_malware": (
        "list_has_any(tags, ['c2', 'malware', 'doublepulsar']) OR cobalt_strike_beacon IS NOT NULL",
        f"array_to_string(tags, ',') || ' | ' || {j('cobalt_strike_beacon', 120)} || ' | '"
        " || left(data, 200)",
        "tag",
    ),
    "tag_ssh_bad_key": (
        "list_contains(tags, 'ssh-bad-key')",
        "coalesce(ssh_fingerprint, '') || ' | ' || left(data, 160)",
        "tag",
    ),
    "tag_eol_product": (
        "list_contains(tags, 'eol-product')",
        "array_to_string(cpe23, ',') || ' | ' || left(data, 160)",
        "tag",
    ),
    "tag_eol_os": (
        "list_contains(tags, 'eol-os')",
        "coalesce(os, '') || ' | ' || array_to_string(cpe23, ',') || ' | ' || left(data, 160)",
        "tag",
    ),
    "tag_honeypot": (
        "list_contains(tags, 'honeypot')",
        "array_to_string(tags, ',') || ' | ' || left(data, 200)",
        "tag",
    ),
    "tag_database": (
        "list_contains(tags, 'database')",
        "array_to_string(proto_keys, ',') || ' | ' || left(data, 220)",
        "tag",
    ),
    "tag_ics": (
        "list_contains(tags, 'ics')",
        "array_to_string(proto_keys, ',') || ' | ' || left(data, 220)",
        "tag",
    ),
    "tag_medical": (
        "list_contains(tags, 'medical')",
        "probe || ' | ' || left(data, 220)",
        "tag",
    ),
    "tag_vpn": (
        "list_contains(tags, 'vpn')",
        "probe || ' | ' || coalesce(http_title, '') || ' | ' || left(data, 160)",
        "tag",
    ),
    "tag_self_signed": (
        "list_contains(tags, 'self-signed')",
        f"{j('cert_subject', 100)} || ' / ' || {j('cert_issuer', 100)}",
        "tag",
    ),
    # Probe name only
    "probe_rat": (
        "probe IN ('darktrack-rat', 'remcos-pro-rat', 'orcus-rat', 'nuclear-rat', 'njrat',"
        " 'blackshades', 'poison-ivy-rat', 'xiaongmai-backdoor', 'ghost-rat', 'njrat78',"
        " 'nanocore-122-rat', 'ta14-353a')",
        "probe || ' | product=' || coalesce(product, '') || ' | ' || left(data, 200)",
        "probe name",
    ),
    # Reply content: unauthenticated access or data exposed
    "ftp_anonymous": (
        "json_extract_string(ftp, '$.anonymous') = 'true'",
        "left(data, 300)",
        "reply content",
    ),
    "smb_anonymous": (
        "json_extract_string(smb, '$.anonymous') = 'true'",
        f"{j(json_extract('smb', '$.shares'), 250)} || ' | os=' || "
        "coalesce(json_extract_string(smb, '$.os'), '')",
        "reply content",
    ),
    "smb_v1": (
        "json_extract_string(smb, '$.smb_version') = '1'",
        "coalesce(json_extract_string(smb, '$.software'), '') || ' | ' || left(data, 200)",
        "reply content",
    ),
    "rsync_noauth": (
        "json_extract_string(rsync, '$.authentication') = 'false'",
        j("json_extract(rsync, '$.modules')", 250),
        "reply content",
    ),
    "redis_noauth": (
        "json_extract(redis, '$.server') IS NOT NULL OR json_extract(redis, '$.keyspace')"
        " IS NOT NULL",
        f"{j(json_extract('redis', '$.keyspace'), 120)} || ' | ' || left(data, 160)",
        "reply content",
    ),
    "mongodb_noauth": (
        "json_extract_string(mongodb, '$.authentication') = 'false'",
        j("json_extract(mongodb, '$.listDatabases')", 300),
        "reply content",
    ),
    "elastic_indices": (
        "json_extract(elastic, '$.indices') IS NOT NULL",
        j("json_extract(elastic, '$.indices')", 300),
        "reply content",
    ),
    "docker_registry_open": (
        "json_extract(docker_registry, '$.repositories') IS NOT NULL",
        j("json_extract(docker_registry, '$.repositories')", 300),
        "reply content",
    ),
    "couchdb_etcd_consul_open": (
        "json_extract(couchdb, '$.dbs') IS NOT NULL OR etcd IS NOT NULL OR consul IS NOT NULL",
        f"{j('couchdb', 120)} || {j('etcd', 120)} || {j('consul', 120)}",
        "reply content",
    ),
    "influxdb_databases": (
        "json_extract(influxdb, '$.databases') IS NOT NULL",
        f"{j(json_extract('influxdb', '$.databases'), 150)} || ' | ' || {j('influxdb', 200)}",
        "reply content",
    ),
    "vnc_noauth": (
        "json_extract(vnc, '$.security_types.\"1\"') IS NOT NULL",
        f"{j(json_extract('vnc', '$.security_types'), 120)} || ' | ' || left(data, 160)",
        "reply content",
    ),
    "ai_llm_open": (
        "ollama IS NOT NULL OR llama_cpp IS NOT NULL OR localai IS NOT NULL OR comfyui IS NOT NULL"
        " OR json_extract_string(anything_llm, '$.RequiresAuth') = 'false'",
        f"{j('ollama', 200)} || {j('llama_cpp', 100)} || {j('localai', 100)} || "
        f"{j('comfyui', 100)}",
        "reply content",
    ),
    "mcp_open": (
        "mcp IS NOT NULL",
        j("mcp", 300),
        "reply content",
    ),
    "lantronix_password": (
        "json_extract(lantronix, '$.password') IS NOT NULL",
        j("lantronix", 300),
        "reply content",
    ),
    "printer_no_password": (
        "json_extract_string(hp_printer_embedded_web_server, '$.password_status') = 'notSet'",
        j("hp_printer_embedded_web_server", 250),
        "reply content",
    ),
    "node_exporter_open": (
        "node_exporter IS NOT NULL",
        j("json_extract(node_exporter, '$.node_uname_info')", 300),
        "reply content",
    ),
    "dns_open_resolver": (
        "json_extract_string(dns, '$.recursive') = 'true'",
        f"{j('dns', 200)} || ' | ' || left(data, 100)",
        "reply content",
    ),
    "ntp_monlist": (
        "json_extract(ntp, '$.monlist') IS NOT NULL AND"
        " json_type(json_extract(ntp, '$.monlist')) = 'OBJECT'",
        j("json_extract(ntp, '$.monlist')", 250),
        "reply content",
    ),
    "snmp_v1_v2": (
        "list_contains(CAST(json_extract(snmp, '$.versions') AS INT[]), 1) OR probe = 'snmp_v2'",
        f"{j('snmp', 250)} || ' | ' || left(data, 100)",
        "reply content",
    ),
    "rdp_standard_security": (
        "list_contains(json_extract_string(rdp_encryption, '$.protocols[*]'),"
        " 'Standard RDP Security')",
        f"{j('rdp_encryption', 250)}",
        "reply content",
    ),
    "rdp_exposed": (
        "rdp_encryption IS NOT NULL OR product = 'Remote Desktop Protocol'",
        f"{PROTO} || ' | ' || left(data, 150)",
        "reply content",
    ),
    "telnet_object": (
        "telnet IS NOT NULL",
        f"{PROTO} || ' | ' || left(data, 220)",
        "reply content",
    ),
    "ics_protocol": (
        "siemens_s7 IS NOT NULL OR bacnet IS NOT NULL OR ethernetip IS NOT NULL OR"
        " codesys IS NOT NULL OR knx IS NOT NULL OR pcworx IS NOT NULL OR mitsubishi_q IS NOT NULL"
        " OR json_extract(opts, '$.modbus') IS NOT NULL",
        "array_to_string(proto_keys, ',') || ' | ' || "
        + j(
            "coalesce(siemens_s7, bacnet, ethernetip, codesys, knx, pcworx, mitsubishi_q,"
            " json_extract(opts, '$.modbus'))",
            250,
        ),
        "reply content",
    ),
    "atg_inventory": (
        "probe = 'automated-tank-gauge' AND contains(data, 'I20100')",
        "left(data, 260)",
        "reply content",
    ),
    "ipmi_exposed": (
        "ipmi IS NOT NULL",
        j("ipmi", 250),
        "reply content",
    ),
    "esxi_exposed": (
        "vmware IS NOT NULL",
        "json_extract_string(vmware, '$.full_name')",
        "reply content",
    ),
    "jdwp": (
        "product = 'Java Debug Wire Protocol'",
        "left(data, 200)",
        "reply content",
    ),
    "http_dir_listing": (
        "http_title LIKE 'Index of /%' OR open_dir IS NOT NULL OR list_contains(tags, 'open-dir')",
        "coalesce(http_title, '') || ' | ' || left(regexp_replace(http_html, '\\s+', ' ', 'g'),"
        " 220)",
        "reply content",
    ),
    "ldap_rootdse_anon": (
        "ldap IS NOT NULL AND json_extract(ldap, '$.errorMessage') IS NULL",
        j("ldap", 250),
        "reply content",
    ),
    "ntlm_info": (
        "ntlm IS NOT NULL",
        j("ntlm", 250),
        "reply content",
    ),
    "screenshot_desktop_nologin": (
        "extra IS NOT NULL AND list_contains(CAST(extra['screenshot.labels'] AS VARCHAR[]),"
        " 'desktop') AND NOT list_contains(CAST(extra['screenshot.labels'] AS VARCHAR[]),"
        " 'login')",
        f"probe || ' | ' || {j(SHOT_LABELS, 60)} || ' | ' || {j(SHOT_TEXT, 200)}",
        "reply content",
    ),
    # TLS / SSH properties
    "cert_expired": (
        "cert_expired",
        "cert_expires || ' | ' || " + j("cert_subject", 120),
        "reply content",
    ),
    "tls_sslv2_sslv3": (
        "list_has_any(tls_versions, ['SSLv2', 'SSLv3'])",
        "array_to_string(tls_versions, ',') || ' | ' || coalesce(tls_cipher_name, '')",
        "reply content",
    ),
    "tls_weak_key": (
        "(cert_pubkey_type = 'rsa' AND cert_pubkey_bits < 2048) OR cert_sig_alg ILIKE '%md5%'",
        "cert_pubkey_type || ' ' || cert_pubkey_bits || ' ' || cert_sig_alg || ' | ' || "
        + j("cert_subject", 120),
        "reply content",
    ),
    "ssh_weak_kex": (
        "list_has_any(json_extract_string(ssh_kex, '$.kex_algorithms[*]'),"
        " ['diffie-hellman-group1-sha1'])"
        " OR list_has_any(json_extract_string(ssh_kex, '$.encryption_algorithms[*]'),"
        " ['arcfour', 'arcfour128', 'arcfour256', 'des-cbc'])",
        "left(data, 120) || ' | ' || " + j("json_extract(ssh_kex, '$.kex_algorithms')", 150),
        "reply content",
    ),
    # Version-inferred
    "cve_kev_unverified": (
        "rec_id IN (SELECT rec_id FROM vuln WHERE kev AND NOT verified)"
        " AND rec_id NOT IN (SELECT rec_id FROM verified)",
        f"{PROTO} || ' | ' || array_to_string(cpe23, ',')",
        "version-inferred",
    ),
}


def evaluate(con, ds: str, name: str) -> None:  # type: ignore[no-untyped-def]
    pred, evidence, proof = SIGNALS[name]
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE m AS SELECT b.*, s.* EXCLUDE (ip) FROM "
        f"(SELECT * FROM banner WHERE {pred}) b "
        f"LEFT JOIN read_parquet('{HERE}/cache/ip_stats.{ds}.parquet') s USING (ip)"
    )
    print(f"signal={name} dataset={ds} proof_type={proof}")
    print(f"predicate: {pred}")
    show(
        con,
        r"""SELECT count(*) AS records, count(DISTINCT ip) AS ips,
          count(*) FILTER (WHERE list_contains(tags, 'honeypot')) AS rec_honeypot_tag,
          count(*) FILTER (WHERE ip_honeypot) AS rec_on_honeypot_ip,
          count(*) FILTER (WHERE list_contains(tags, 'cdn')) AS rec_cdn_tag,
          count(*) FILTER (WHERE list_contains(tags, 'cloud')) AS rec_cloud_tag,
          count(*) FILTER (WHERE ip_ports >= 20) AS rec_on_20plus_port_ip,
          count(DISTINCT ip) FILTER (WHERE ip_ports >= 20) AS ips_20plus_ports
        FROM m""",
        "prevalence and carriers",
    )
    for col in ("ip", "asn", "org", "product", "port"):
        show(
            con,
            f"""WITH t AS (SELECT CAST({col} AS VARCHAR) AS v, count(*) AS n FROM m GROUP BY 1),
                tot AS (SELECT sum(n) AS s FROM t)
            SELECT v AS {col}, n, round(100.0 * n / s, 1) AS pct,
                   round(100.0 * sum(n) OVER (ORDER BY n DESC, v
                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) / s, 1) AS cum_pct
            FROM t, tot ORDER BY n DESC, v LIMIT 5""",
            f"top 5 {col}",
        )
    show(
        con,
        r"""WITH h AS (
          SELECT *,
            len(hostnames) > 0 AS has_host,
            len(list_filter(hostnames,
                lambda x: NOT regexp_matches(x, '\d{1,3}[-.x]\d{1,3}[-.x]\d{1,3}'))) > 0
              AS has_non_iplike_host,
            cert_subject->>'CN' IS NOT NULL
              AND regexp_matches(cert_subject->>'CN', '[a-zA-Z]')
              AND contains(cert_subject->>'CN', '.') AS has_cert_domain_cn,
            org = isp AS org_eq_isp,
            cloud_provider IS NOT NULL AS on_cloud
          FROM m)
        SELECT count(*) AS records,
          round(100.0 * count(*) FILTER (WHERE has_host) / count(*), 1) AS pct_hostname,
          round(100.0 * count(*) FILTER (WHERE has_non_iplike_host) / count(*), 1)
            AS pct_non_iplike_hostname,
          round(100.0 * count(*) FILTER (WHERE has_cert_domain_cn) / count(*), 1)
            AS pct_cert_domain_cn,
          round(100.0 * count(*) FILTER (WHERE has_non_iplike_host OR has_cert_domain_cn)
            / count(*), 1) AS pct_any_name,
          round(100.0 * count(*) FILTER (WHERE org_eq_isp) / count(*), 1) AS pct_org_eq_isp,
          round(100.0 * count(*) FILTER (WHERE on_cloud) / count(*), 1) AS pct_cloud_provider
        FROM h""",
        "attributable share (names only; no attribution built)",
    )
    show(
        con,
        f"""SELECT rec_id, ip, port, transport AS tr, probe, {PROTO} AS product,
              left(org, 40) AS org, array_to_string(tags, ',') AS tags,
              ip_ports, left(array_to_string(hostnames, ','), 50) AS hostnames,
              {evidence} AS evidence
            FROM m ORDER BY md5(rec_id) LIMIT 12""",
        "12 records, ORDER BY md5(rec_id)",
        width=400,
    )


def main() -> None:
    con, ds = connect()
    con.execute("CREATE TEMP TABLE verified AS SELECT DISTINCT rec_id FROM vuln WHERE verified")
    names = sys.argv[2:] or list(SIGNALS)
    out = HERE / "out" / "signals"
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = out / f"{name}.{ds}.txt"
        stdout = sys.stdout
        with open(path, "w") as f:
            sys.stdout = f
            try:
                evaluate(con, ds, name)
            finally:
                sys.stdout = stdout
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
