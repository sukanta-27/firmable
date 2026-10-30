"""Flatten a Shodan NDJSON banner dump into two Parquet tables.

    banners.parquet  one row per record: core fields flattened, protocol objects as raw JSON text
    vulns.parquet    one row per (record, CVE)

Usage:
    flatten_duckdb.py INPUT OUT_DIR [--compression none|gzip|zstd] [--threads N] [--memory 12GB]

The input is parsed exactly once. Long text fields (HTML, raw banner) are
truncated so the output stays small enough to query interactively; their full
lengths are kept so truncation is visible.

Type mismatches abort the run rather than dropping rows silently. Fields whose
type varies across records are declared JSON and parsed at query time.
"""
import argparse
import os
import time

import duckdb

# Every protocol-specific top-level key seen in the 2026-10-26 file (163 keys from a
# full-file census). Kept as raw JSON text so a new field inside one never breaks
# ingestion. A key that is absent from a record yields NULL. Unknown new keys in
# future files are ignored by read_json; re-run the census to extend this list.
PROTO_JSON = """
afp airplay amqp anerma_cf_forth anything_llm auerswald_compact_series bacnet beanstalk bgp bitcoin
cassandra checkpoint chroma chromecast cimd cisco_anyconnect cisco_ipsla clickhouse coap
cobalt_strike_beacon codesys comfyui consul couchbase_server couchdb dahua dahua_dvr_web dav dd_wrt
digi dns docker_registry dogecoin_node domoticz draytek_vigor elastic epmd etcd ethereum_p2p
ethereum_rpc ethernetip fast_reverse_proxy flink fortinet ftp ganglia gemini gl_inet h323 handpunch
hermes_agent hikvision home_assistant homebridge homematic_ccu hp_ilo hp_printer_embedded_web_server
huawei_home_gateway ibm_db2 influxdb ip_camera ipmi ipp_cups isakmp iscsi knx kubernetes
kyocera_printer_panel l2tp lantronix ldap litecoin_node llama_cpp localai mcp mdns microsoft_exchange
mikrotik_routeros mikrotik_winbox milesight_routers milvus minecraft mitsubishi_q monero mongodb
mpls_ldp mqtt msrpc mssql_ssrp mysql mysqlx nats ndmp neo4j_browser netbios netdata netgear netusb
nmea node_exporter nsq ntlm ntp ntrip ollama open_dir openflow openwebnet oracle_tnslsnr pcworx
pgbouncer philips_hue plex pptp pqube3_power_analyzers qnap questdb radius raspberry_shake
rdp_encryption realport redis reolink_baichuan rip ripple rsync samsung_syncthru_web_service
samsung_tv seven_days_to_die shelly siemens_s7 sip skywalking smb snmp sonicwall sony_bravia
spotify_connect steam_a2s steam_ihs stun superset synology_dsm synology_srm tacacs telnet tibia tidb
tilginAB_home_gateway tp_link_kasa tp_link_kasa_new trane_tracer_sc ubiquiti upnp vault vertx vmware
vnc wg_easy windows_exporter xiaomi_miio yeelight zeromq mac
""".split()

COLUMNS = {
    "_shodan": "STRUCT(id VARCHAR, module VARCHAR, crawler VARCHAR, region VARCHAR, ptr BOOLEAN, "
               "options STRUCT(hostname VARCHAR, scan VARCHAR, referrer VARCHAR))",
    "ip_str": "VARCHAR", "ipv6": "VARCHAR", "port": "INTEGER", "transport": "VARCHAR",
    "timestamp": "VARCHAR", "asn": "VARCHAR", "org": "VARCHAR", "isp": "VARCHAR", "os": "VARCHAR",
    "product": "VARCHAR", "version": "VARCHAR", "info": "VARCHAR", "devicetype": "VARCHAR",
    "vendor": "VARCHAR", "device": "VARCHAR", "platform": "VARCHAR", "title": "VARCHAR",
    "html": "VARCHAR", "link": "VARCHAR", "uptime": "BIGINT", "hash": "BIGINT",
    "hostnames": "VARCHAR[]", "domains": "VARCHAR[]", "tags": "VARCHAR[]", "cpe23": "VARCHAR[]",
    "location": "STRUCT(country_code VARCHAR, country_name VARCHAR, city VARCHAR, "
                "region_code VARCHAR, latitude DOUBLE, longitude DOUBLE)",
    "cloud": "STRUCT(provider VARCHAR, region VARCHAR, service VARCHAR)",
    "http": "STRUCT(status INTEGER, title VARCHAR, server VARCHAR, host VARCHAR, html VARCHAR, "
            "html_hash BIGINT, headers_hash BIGINT, location VARCHAR, waf VARCHAR, robots VARCHAR, "
            "securitytxt VARCHAR, sitemap VARCHAR, components MAP(VARCHAR, JSON), redirects JSON, "
            "favicon STRUCT(hash BIGINT, location VARCHAR), headers JSON)",
    "ssl": "STRUCT(cert STRUCT(subject JSON, issuer JSON, expired BOOLEAN, expires VARCHAR, "
           "issued VARCHAR, sig_alg VARCHAR, pubkey STRUCT(type VARCHAR, bits INTEGER), "
           "fingerprint STRUCT(sha256 VARCHAR), extensions STRUCT(name VARCHAR, data VARCHAR)[]), "
           "versions VARCHAR[], cipher STRUCT(name VARCHAR, version VARCHAR, bits INTEGER), "
           "ciphers STRUCT(name VARCHAR, version VARCHAR)[], jarm VARCHAR, ja3s VARCHAR, "
           "alpn VARCHAR[], dhparams STRUCT(bits INTEGER, fingerprint VARCHAR), chain VARCHAR[], "
           "trust JSON)",
    "opts": "STRUCT(vulns VARCHAR[], heartbleed VARCHAR)",
    "vulns": "MAP(VARCHAR, STRUCT(cvss DOUBLE, cvss_version DOUBLE, cvss_v2 DOUBLE, epss DOUBLE, "
             "ranking_epss DOUBLE, verified BOOLEAN, kev BOOLEAN, ransomware_campaign VARCHAR))",
    "ssh": "STRUCT(type VARCHAR, cipher VARCHAR, mac VARCHAR, hassh VARCHAR, kex STRUCT("
           "kex_algorithms VARCHAR[], encryption_algorithms VARCHAR[], mac_algorithms VARCHAR[], "
           "server_host_key_algorithms VARCHAR[]))",
    "screenshot": "JSON",
    "data": "VARCHAR",
    **{k: "JSON" for k in PROTO_JSON},
}

HTML_KEEP = 4000
BANNER_KEEP = 3000
SAN_KEEP = 2048


def projection() -> str:
    proto_cols = ",\n  ".join(f"{k}::VARCHAR AS {k}" for k in PROTO_JSON)
    proto_keys = ", ".join(f"CASE WHEN {k} IS NOT NULL THEN '{k}' END" for k in PROTO_JSON + ["screenshot"])
    return f"""
  _shodan.id AS rec_id,
  _shodan.module AS module, _shodan.crawler AS crawler, _shodan.region AS crawler_region,
  _shodan.ptr AS ptr, _shodan.options.hostname AS sni_hostname, _shodan.options.scan AS scan_id,
  ip_str, ipv6, port, transport, try_cast("timestamp" AS TIMESTAMP) AS ts,
  asn, org, isp, os, product, version, info, devicetype, vendor, device, platform,
  title AS top_title, left(html, {HTML_KEEP}) AS top_html, link, uptime, hash AS banner_hash,
  hostnames, domains, tags, cpe23,
  location.country_code AS country_code, location.country_name AS country_name,
  location.city AS city, location.region_code AS region_code,
  location.latitude AS latitude, location.longitude AS longitude,
  cloud.provider AS cloud_provider, cloud.region AS cloud_region, cloud.service AS cloud_service,
  http IS NOT NULL AS has_http,
  http.status AS http_status, http.title AS http_title, http.server AS http_server,
  http.host AS http_host, http.html_hash AS http_html_hash, http.headers_hash AS http_headers_hash,
  http.location AS http_location, http.waf AS http_waf,
  http.robots IS NOT NULL AS http_has_robots, http.securitytxt AS http_securitytxt,
  http.sitemap IS NOT NULL AS http_has_sitemap, map_keys(http.components) AS http_components,
  json_array_length(http.redirects) AS http_redirects_n, http.favicon.hash AS http_favicon_hash,
  http.headers::VARCHAR AS http_headers, length(http.html) AS http_html_len,
  left(http.html, {HTML_KEEP}) AS http_html,
  ssl IS NOT NULL AS has_ssl,
  json_extract_string(ssl.cert.subject, '$.CN') AS ssl_subject_cn,
  json_extract_string(ssl.cert.subject, '$.O') AS ssl_subject_o,
  json_extract_string(ssl.cert.subject, '$.OU') AS ssl_subject_ou,
  json_extract_string(ssl.cert.subject, '$.C') AS ssl_subject_c,
  json_extract_string(ssl.cert.issuer, '$.CN') AS ssl_issuer_cn,
  json_extract_string(ssl.cert.issuer, '$.O') AS ssl_issuer_o,
  ssl.cert.expired AS ssl_expired, ssl.cert.expires AS ssl_expires, ssl.cert.issued AS ssl_issued,
  ssl.cert.sig_alg AS ssl_sig_alg, ssl.cert.pubkey.type AS ssl_pubkey_type,
  ssl.cert.pubkey.bits AS ssl_pubkey_bits, ssl.cert.fingerprint.sha256 AS ssl_fp_sha256,
  left(list_filter(ssl.cert.extensions, lambda x: x.name = 'subjectAltName')[1].data, {SAN_KEEP}) AS ssl_san_raw,
  ssl.versions AS ssl_versions, ssl.cipher.name AS ssl_cipher_name,
  ssl.cipher.version AS ssl_cipher_version, ssl.cipher.bits AS ssl_cipher_bits,
  list_transform(ssl.ciphers, lambda x: x.name) AS ssl_ciphers,
  ssl.jarm AS ssl_jarm, ssl.ja3s AS ssl_ja3s, ssl.alpn AS ssl_alpn,
  ssl.dhparams.bits AS ssl_dh_bits, ssl.dhparams.fingerprint AS ssl_dh_fingerprint,
  len(ssl.chain) AS ssl_chain_len, ssl.trust::VARCHAR AS ssl_trust,
  opts.vulns AS opts_vulns, opts.heartbleed AS opts_heartbleed,
  vulns,
  cardinality(vulns) AS n_vulns,
  ssh.type AS ssh_type, ssh.cipher AS ssh_cipher, ssh.mac AS ssh_mac, ssh.hassh AS ssh_hassh,
  ssh.kex.kex_algorithms AS ssh_kex_algorithms,
  ssh.kex.encryption_algorithms AS ssh_encryption_algorithms,
  ssh.kex.mac_algorithms AS ssh_mac_algorithms,
  ssh.kex.server_host_key_algorithms AS ssh_host_key_algorithms,
  screenshot IS NOT NULL AS has_screenshot,
  list_filter([{proto_keys}], lambda x: x IS NOT NULL) AS proto_keys,
  {proto_cols},
  length(data) AS data_len, left(data, {BANNER_KEEP}) AS data
"""


VULNS_SQL = """
SELECT rec_id, e.key AS cve, e.value.cvss AS cvss, e.value.cvss_version AS cvss_version,
       e.value.cvss_v2 AS cvss_v2, e.value.epss AS epss, e.value.ranking_epss AS ranking_epss,
       e.value.verified AS verified, e.value.kev AS kev, e.value.ransomware_campaign AS ransomware_campaign
FROM read_parquet('{banners}'), UNNEST(map_entries(vulns)) AS t(e)
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("out_dir")
    ap.add_argument("--compression", default="none")
    ap.add_argument("--threads", type=int, default=os.cpu_count())
    ap.add_argument("--memory", default="12GB")
    ap.add_argument("--ignore-errors", action="store_true",
                    help="skip lines DuckDB cannot parse (lone UTF-16 surrogates); reconcile row counts after")
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    banners = os.path.join(args.out_dir, "banners.parquet")
    vulns = os.path.join(args.out_dir, "vulns.parquet")

    con = duckdb.connect()
    con.execute(f"SET threads={args.threads}")
    con.execute(f"SET memory_limit='{args.memory}'")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET temp_directory='{os.path.join(args.out_dir, 'tmp')}'")

    cols = ", ".join(f"'{k}': '{v}'" for k, v in COLUMNS.items())
    src = (f"read_json('{args.input}', format='newline_delimited', compression='{args.compression}', "
           f"columns={{{cols}}}, maximum_object_size=67108864, "
           f"ignore_errors={'true' if args.ignore_errors else 'false'})")

    t0 = time.time()
    con.execute(f"COPY (SELECT {projection()} FROM {src}) TO '{banners}' "
                "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)")
    t1 = time.time()
    con.execute(f"COPY ({VULNS_SQL.format(banners=banners)}) TO '{vulns}' (FORMAT PARQUET, COMPRESSION ZSTD)")
    t2 = time.time()
    n = con.execute(f"SELECT count(*) FROM read_parquet('{banners}')").fetchone()[0]
    nv = con.execute(f"SELECT count(*) FROM read_parquet('{vulns}')").fetchone()[0]
    print(f"banners rows={n:,} in {t1 - t0:.1f}s -> {os.path.getsize(banners) / 1e6:.1f} MB")
    print(f"vulns   rows={nv:,} in {t2 - t1:.1f}s -> {os.path.getsize(vulns) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
