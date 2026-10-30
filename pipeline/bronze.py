"""Bronze: every record of one source file, typed, with nothing lost or invented.

The source is streamed twice, never unpacked to disk:

1. Record pass -> banner. One row per line; a line that is not a JSON object is kept as a
   row with `parse_error` set and its text excerpted, so it is counted and never mistaken
   for a real record. Downstream reads `WHERE parse_error IS NULL`.
2. CVE pass    -> vuln + cve_text. One row per record x CVE, and the CVE descriptions.

Each pass is one plain COPY that streams to a single file. Splitting a pass's output,
by rewriting it or by a partitioned write, buffered tens of GB on the full file.

The second pass exists because a CVE's summary and references describe the CVE, not the
host: on the 2026-10-26 file 20,988,468 record x CVE entries carry 39.2 GB of that text,
which is 13.7 MB once stored per CVE. Keeping it inside banner made the table too heavy
to rewrite, and a single DuckDB pass writes only one table shape, so the CVE tables get a
pass of their own that skips every line without a "vulns" key.
"""

import logging
import resource
import shutil
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from pipeline.meta import Check, Manifest, RunLog, Status, manifest_path, write_json

TABLES = ("banner", "vuln", "cve_text")
TRUNCATE_AT = 4000
SAMPLE_SECONDS = 10
# Measured on a 2M-line slice of the 2026-10-26 file: pass 1 peaked at 17.1 GB of DuckDB
# memory with 12 threads (limit 19.1 GiB) and 11.1 GB with 8, at the same speed.
THREADS = 8

logger = logging.getLogger("pipeline.bronze")

TEXT, INT, FLOAT, BOOL, LIST, JSON, TRUNC, KEYS = (
    "text",
    "int",
    "float",
    "bool",
    "list",
    "json",
    "trunc",
    "keys",
)

# (column, dotted path in the Shodan record, kind). Every key a record can carry is
# either here, in PROTOCOLS, in DROPPED, or lands in `extra`, so nothing vanishes.
COLUMNS: list[tuple[str, str, str]] = [
    ("rec_id", "_shodan.id", TEXT),
    ("scanner", "_shodan.crawler", TEXT),
    ("scanner_region", "_shodan.region", TEXT),
    ("probe", "_shodan.module", TEXT),
    ("ptr", "_shodan.ptr", BOOL),
    ("scan_hostname", "_shodan.options.hostname", TEXT),
    ("scan_referrer", "_shodan.options.referrer", TEXT),
    ("scan_id", "_shodan.options.scan", TEXT),
    ("ip_str", "ip_str", TEXT),
    ("ipv6", "ipv6", TEXT),
    ("port", "port", INT),
    ("transport", "transport", TEXT),
    ("timestamp", "timestamp", TEXT),
    ("asn", "asn", TEXT),
    ("org", "org", TEXT),
    ("isp", "isp", TEXT),
    ("os", "os", TEXT),
    ("product", "product", TEXT),
    ("version", "version", TEXT),
    ("info", "info", TEXT),
    ("devicetype", "devicetype", TEXT),
    ("vendor", "vendor", TEXT),
    ("device", "device", TEXT),
    ("platform", "platform", TEXT),
    ("top_title", "title", TEXT),
    ("top_html", "html", TRUNC),
    ("link", "link", TEXT),
    ("uptime", "uptime", INT),
    ("banner_hash", "hash", INT),
    ("cpe", "cpe", LIST),
    ("cpe23", "cpe23", LIST),
    ("cpe23_hash", "cpe23_hash", INT),
    ("tags", "tags", LIST),
    ("hostnames", "hostnames", LIST),
    ("domains", "domains", LIST),
    ("data", "data", TRUNC),
    ("country_code", "location.country_code", TEXT),
    ("country_code3", "location.country_code3", TEXT),
    ("country_name", "location.country_name", TEXT),
    ("city", "location.city", TEXT),
    ("region_code", "location.region_code", TEXT),
    ("postal_code", "location.postal_code", TEXT),
    ("area_code", "location.area_code", TEXT),
    ("dma_code", "location.dma_code", TEXT),
    ("latitude", "location.latitude", FLOAT),
    ("longitude", "location.longitude", FLOAT),
    ("cloud_provider", "cloud.provider", TEXT),
    ("cloud_region", "cloud.region", TEXT),
    ("cloud_service", "cloud.service", TEXT),
    ("http_status", "http.status", INT),
    ("http_host", "http.host", TEXT),
    ("http_location", "http.location", TEXT),
    ("http_title", "http.title", TEXT),
    ("http_title_hash", "http.title_hash", INT),
    ("http_server", "http.server", TEXT),
    ("http_server_hash", "http.server_hash", INT),
    ("http_waf", "http.waf", TEXT),
    ("http_html", "http.html", TRUNC),
    ("http_html_hash", "http.html_hash", INT),
    ("http_dom_hash", "http.dom_hash", INT),
    ("http_headers", "http.headers", JSON),
    ("http_headers_hash", "http.headers_hash", INT),
    ("http_components", "http.components", JSON),
    ("http_components_hash", "http.components_hash", INT),
    ("http_redirects", "http.redirects", JSON),
    ("http_identifiers", "http.identifiers", JSON),
    ("http_robots", "http.robots", TEXT),
    ("http_robots_hash", "http.robots_hash", INT),
    ("http_securitytxt", "http.securitytxt", TEXT),
    ("http_securitytxt_hash", "http.securitytxt_hash", INT),
    ("http_sitemap", "http.sitemap", TEXT),
    ("http_sitemap_hash", "http.sitemap_hash", INT),
    ("http_favicon_hash", "http.favicon.hash", INT),
    ("http_favicon_location", "http.favicon.location", TEXT),
    ("tls_versions", "ssl.versions", LIST),
    ("tls_cipher_name", "ssl.cipher.name", TEXT),
    ("tls_cipher_version", "ssl.cipher.version", TEXT),
    ("tls_cipher_bits", "ssl.cipher.bits", INT),
    ("tls_ciphers", "ssl.ciphers", JSON),
    ("tls_alpn", "ssl.alpn", LIST),
    ("tls_jarm", "ssl.jarm", TEXT),
    ("tls_ja3s", "ssl.ja3s", TEXT),
    ("tls_kex_groups", "ssl.kex_groups", LIST),
    ("tls_handshake_states", "ssl.handshake_states", LIST),
    ("tls_tlsext", "ssl.tlsext", JSON),
    ("tls_unstable", "ssl.unstable", JSON),
    ("tls_dhparams", "ssl.dhparams", JSON),
    ("tls_acceptable_cas", "ssl.acceptable_cas", JSON),
    ("tls_ocsp", "ssl.ocsp", JSON),
    ("tls_trust", "ssl.trust", JSON),
    ("tls_chain_sha256", "ssl.chain_sha256", LIST),
    ("cert_subject", "ssl.cert.subject", JSON),
    ("cert_issuer", "ssl.cert.issuer", JSON),
    ("cert_expired", "ssl.cert.expired", BOOL),
    ("cert_issued", "ssl.cert.issued", TEXT),
    ("cert_expires", "ssl.cert.expires", TEXT),
    ("cert_sig_alg", "ssl.cert.sig_alg", TEXT),
    # Integer on most records, float on some: kept as the JSON number text.
    ("cert_serial", "ssl.cert.serial", JSON),
    ("cert_version", "ssl.cert.version", INT),
    ("cert_pubkey_type", "ssl.cert.pubkey.type", TEXT),
    ("cert_pubkey_bits", "ssl.cert.pubkey.bits", INT),
    ("cert_sha256", "ssl.cert.fingerprint.sha256", TEXT),
    ("cert_sha1", "ssl.cert.fingerprint.sha1", TEXT),
    ("cert_extensions", "ssl.cert.extensions", JSON),
    ("ssh_type", "ssh.type", TEXT),
    ("ssh_cipher", "ssh.cipher", TEXT),
    ("ssh_mac", "ssh.mac", TEXT),
    ("ssh_hassh", "ssh.hassh", TEXT),
    ("ssh_fingerprint", "ssh.fingerprint", TEXT),
    ("ssh_key", "ssh.key", TEXT),
    ("ssh_kex", "ssh.kex", JSON),
    ("screenshot_mime", "screenshot.mime", TEXT),
    ("opts", "opts", JSON),
    ("cves", "vulns", KEYS),  # IDs only; the entries go to the vuln tables
]

# Bulky or redundant, and recoverable from the source file that landing keeps.
DROPPED = {
    "ip",  # integer form of ip_str
    "http.favicon.data",
    "ssl.chain",  # PEM text; ssl.chain_sha256 identifies each certificate
    "screenshot.data",
}

# Every protocol-specific top-level object in the 2026-10-26 file's key census. Each is
# kept as JSON text in a column of its own name.
PROTOCOLS = [
    "afp",
    "airplay",
    "amqp",
    "anerma_cf_forth",
    "anything_llm",
    "auerswald_compact_series",
    "bacnet",
    "beanstalk",
    "bgp",
    "bitcoin",
    "cassandra",
    "checkpoint",
    "chroma",
    "chromecast",
    "cimd",
    "cisco_anyconnect",
    "cisco_ipsla",
    "cisco_sdwan",
    "clickhouse",
    "coap",
    "cobalt_strike_beacon",
    "codesys",
    "comfyui",
    "consul",
    "couchbase_server",
    "couchdb",
    "dahua",
    "dahua_dvr_web",
    "dav",
    "dd_wrt",
    "digi",
    "dns",
    "docker_registry",
    "dogecoin_node",
    "domoticz",
    "draytek_vigor",
    "elastic",
    "epmd",
    "etcd",
    "ethereum_p2p",
    "ethereum_rpc",
    "ethernetip",
    "fast_reverse_proxy",
    "flink",
    "fortinet",
    "ftp",
    "ganglia",
    "gemini",
    "gl_inet",
    "h323",
    "handpunch",
    "hermes_agent",
    "hikvision",
    "home_assistant",
    "homebridge",
    "homematic_ccu",
    "hp_ilo",
    "hp_printer_embedded_web_server",
    "huawei_home_gateway",
    "ibm_db2",
    "influxdb",
    "ip_camera",
    "ipmi",
    "ipp_cups",
    "isakmp",
    "iscsi",
    "knx",
    "kubernetes",
    "kyocera_printer_panel",
    "l2tp",
    "lantronix",
    "ldap",
    "litecoin_node",
    "llama_cpp",
    "localai",
    "mac",
    "mcp",
    "mdns",
    "microsoft_exchange",
    "mikrotik_routeros",
    "mikrotik_winbox",
    "milesight_routers",
    "milvus",
    "minecraft",
    "mitsubishi_q",
    "monero",
    "mongodb",
    "mpls_ldp",
    "mqtt",
    "msrpc",
    "mssql_ssrp",
    "mysql",
    "mysqlx",
    "nats",
    "ndmp",
    "neo4j_browser",
    "netbios",
    "netdata",
    "netgear",
    "netusb",
    "nmea",
    "node_exporter",
    "nsq",
    "ntlm",
    "ntp",
    "ntrip",
    "ollama",
    "open_dir",
    "openflow",
    "openwebnet",
    "oracle_tnslsnr",
    "pcworx",
    "pgbouncer",
    "philips_hue",
    "plex",
    "pptp",
    "pqube3_power_analyzers",
    "qnap",
    "questdb",
    "radius",
    "raspberry_shake",
    "rdp_encryption",
    "realport",
    "redis",
    "reolink_baichuan",
    "rip",
    "ripple",
    "rsync",
    "samsung_syncthru_web_service",
    "samsung_tv",
    "seven_days_to_die",
    "shelly",
    "siemens_s7",
    "sip",
    "skywalking",
    "smb",
    "snmp",
    "sonicwall",
    "sony_bravia",
    "spotify_connect",
    "stun",
    "steam_a2s",
    "steam_ihs",
    "superset",
    "synology_dsm",
    "synology_srm",
    "tacacs",
    "tcp",
    "telnet",
    "tibia",
    "tidb",
    "tilginAB_home_gateway",
    "tp_link_kasa",
    "tp_link_kasa_new",
    "trane_tracer_sc",
    "ubiquiti",
    "udp",
    "upnp",
    "vault",
    "vertx",
    "vmware",
    "vnc",
    "wg_easy",
    "windows_exporter",
    "xiaomi_miio",
    "yeelight",
    "zeromq",
]

# Each JSON value is checked for its kind before it is cast. json_transform alone turns a
# mismatch into NULL, and CAST('1.5' AS BIGINT) rounds; both would lose data silently.
MACROS = r"""
CREATE MACRO jmap(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN left(j, 1) = '{' THEN json_transform(j, '"MAP(VARCHAR, JSON)"')
  ELSE error('bronze: ' || path || ' is not an object: ' || left(j, 200)) END;
CREATE MACRO as_text(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN left(j, 1) = '"' THEN j ->> '$'
  ELSE error('bronze: ' || path || ' is not a string: ' || left(j, 200)) END;
CREATE MACRO as_int(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN regexp_full_match(j, '-?[0-9]+') THEN CAST(j AS BIGINT)
  ELSE error('bronze: ' || path || ' is not an integer: ' || left(j, 200)) END;
CREATE MACRO as_float(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN regexp_full_match(j, '-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?') THEN CAST(j AS DOUBLE)
  ELSE error('bronze: ' || path || ' is not a number: ' || left(j, 200)) END;
CREATE MACRO as_bool(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN j IN ('true', 'false') THEN CAST(j AS BOOLEAN)
  ELSE error('bronze: ' || path || ' is not a boolean: ' || left(j, 200)) END;
CREATE MACRO as_list(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN left(j, 1) = '[' THEN json_transform(j, '["VARCHAR"]')
  ELSE error('bronze: ' || path || ' is not a list: ' || left(j, 200)) END;
CREATE MACRO as_keys(j, path) AS CASE
  WHEN j IS NULL THEN NULL
  WHEN left(j, 1) = '{' THEN json_keys(j)
  ELSE error('bronze: ' || path || ' is not an object: ' || left(j, 200)) END;
"""

# Fields of one entry in a record's `vulns` object, keyed by CVE ID.
VULN_FIELDS: list[tuple[str, str]] = [
    ("cvss", FLOAT),
    ("cvss_version", FLOAT),
    ("cvss_v2", FLOAT),
    ("epss", FLOAT),
    ("ranking_epss", FLOAT),
    ("verified", BOOL),
    ("kev", BOOL),
    ("ransomware_campaign", TEXT),
]
CVE_TEXT_FIELDS: list[tuple[str, str]] = [("summary", TEXT), ("references", LIST)]


def _map_var(obj: str) -> str:
    """SQL name of the column holding the parsed map for an object path ("" is the record)."""
    return "m" if obj == "" else "m_" + obj.replace(".", "_")


def _value(path: str) -> str:
    """SQL expression for the raw JSON text at a dotted path."""
    parent, _, key = path.rpartition(".")
    return f"{_map_var(parent)}['{key}']"


def _object_paths() -> list[str]:
    """Every object the record pass parses into a map, parents before children."""
    paths = {"": None}
    for p in [p for _, p, _ in COLUMNS] + sorted(DROPPED):
        parts = p.split(".")
        for i in range(1, len(parts)):
            paths[".".join(parts[:i])] = None
    return sorted(paths, key=lambda p: (p.count(".") if p else -1, p))


def _children(obj: str) -> set[str]:
    """Keys of an object that bronze knows about; any other key goes to `extra`."""
    prefix = obj + "." if obj else ""
    paths = [p for _, p, _ in COLUMNS] + list(DROPPED) + _object_paths()
    children = {p[len(prefix) :].split(".")[0] for p in paths if p.startswith(prefix) and p != obj}
    return children | (set(PROTOCOLS) if obj == "" else set())


def _cast(value: str, path: str, kind: str) -> str:
    """SQL that checks a JSON value is of the expected kind and casts it."""
    match kind:
        case "text" | "int" | "float" | "bool" | "list" | "keys":
            return f"as_{kind}({value}, '{path}')"
        case "json":
            return value
    raise ValueError(kind)


def _column_sql(name: str, path: str, kind: str) -> list[str]:
    """SELECT items for one banner column; truncated text also gets its full length."""
    if kind == TRUNC:
        text = _cast(_value(path), path, TEXT)
        return [f"left({text}, {TRUNCATE_AT}) AS {name}", f"length({text}) AS {name}_len"]
    return [f"{_cast(_value(path), path, kind)} AS {name}"]


def _unknown_entries(map_sql: str, known: set[str], prefix: str) -> str:
    """SQL list of {key, value} for the keys of a parsed map that are not in `known`."""
    names = ", ".join(f"'{k}'" for k in sorted(known))
    label = f"'{prefix}.' || " if prefix else ""
    return (
        f"coalesce(list_transform(list_filter(map_entries({map_sql}), "
        f"lambda e: NOT list_contains([{names}], e.key)), "
        f"lambda e: {{'key': {label}e.key, 'value': e.value}}), [])"
    )


def _source_sql(manifest: Manifest) -> str:
    """DuckDB table function that streams the source file one line per row."""
    path = manifest.source_uri.replace("'", "''")
    # delim \x01 never appears unescaped in valid JSON, so each line lands whole in one column.
    # A buffer as large as max_line_size lets DuckDB split the scan across threads; with the
    # default buffer it ran on about one core.
    return (
        f"read_csv('{path}', columns={{'line': 'VARCHAR'}}, delim='\x01', quote='', escape='', "
        f"header=false, auto_detect=false, max_line_size=67108864, buffer_size=67108864, "
        f"compression='{manifest.compression}')"
    )


def record_pass_sql(source: str) -> str:
    """Query for pass 1: one row per source line; unreadable lines get `parse_error`.

    Each record is parsed once into a map of its top-level keys, and each nested object
    again from its own text. The map is what lets unknown keys reach `extra`.
    """
    layers = [
        f"SELECT line, json_valid(line) AND left(ltrim(line), 1) = '{{' AS ok FROM {source}",
        "SELECT *, CASE WHEN ok THEN json_transform(line, '\"MAP(VARCHAR, JSON)\"') END AS m "
        "FROM l0",
    ]
    for obj in _object_paths()[1:]:
        parent, _, key = obj.rpartition(".")
        layers.append(
            f"SELECT *, jmap({_map_var(parent)}['{key}'], '{obj}') AS {_map_var(obj)} "
            f"FROM l{len(layers) - 1}"
        )
    ctes = ",\n".join(f"l{i} AS ({sql})" for i, sql in enumerate(layers))
    cols = [c for spec in COLUMNS for c in _column_sql(*spec)]
    protos = [f"m['{p}'] AS {p}" for p in PROTOCOLS]
    proto_list = ", ".join(f"'{p}'" for p in PROTOCOLS)
    extra = ", ".join(
        _unknown_entries(_map_var(obj), _children(obj), obj) for obj in _object_paths()
    )
    return f"""
WITH {ctes},
extracted AS (
  SELECT ok, line,
    {",\n    ".join(cols)},
    {",\n    ".join(protos)},
    list_filter(map_keys(m), lambda k: list_contains([{proto_list}], k)) AS proto_keys,
    list_concat({extra}) AS extra_entries
  FROM l{len(layers) - 1}
)
SELECT
  CASE WHEN ok THEN NULL
       WHEN NOT json_valid(line) THEN 'invalid_json'
       ELSE 'not_an_object' END AS parse_error,
  CASE WHEN NOT ok THEN left(line, 2000) END AS parse_error_excerpt,
  * EXCLUDE (ok, line, ip_str, ipv6, "timestamp", extra_entries)
    REPLACE (CASE WHEN ok THEN rec_id
                  ELSE regexp_extract(line, '"id":\\s*"([0-9a-f-]{{36}})"', 1) END AS rec_id),
  CASE WHEN ip_str IS NOT NULL AND ipv6 IS NOT NULL
         THEN error('bronze: record ' || rec_id || ' has both ip_str and ipv6')
       ELSE coalesce(ip_str, ipv6) END AS ip,
  CASE WHEN ip_str IS NOT NULL THEN 4 WHEN ipv6 IS NOT NULL THEN 6 END AS ip_version,
  CAST("timestamp" AS TIMESTAMP) AS ts,
  CASE WHEN len(extra_entries) > 0 THEN map_from_entries(extra_entries) END AS extra
FROM extracted
"""


def cve_pass_sql(source: str) -> str:
    """Query for pass 2: one row per record that has CVEs, with its `vulns` JSON untouched.

    Lines without the text "vulns" are skipped before any JSON is parsed. Unreadable
    lines are already flagged in banner by pass 1, so they are skipped here.
    """
    # Only two fields are needed, so they are extracted directly. Parsing each whole line
    # into a map, HTML included, ran out of memory at 12 threads on a 2M-line slice of the
    # 2026-10-26 file; extracting peaked at 12.2 GB with identical output.
    return f"""
WITH records AS (
  -- The CASE is needed: DuckDB may evaluate the extract before the WHERE has removed the
  -- line, and an unparseable line then aborts the whole pass.
  SELECT CASE WHEN json_valid(line) AND left(ltrim(line), 1) = '{{'
              THEN json_extract(line, ['$._shodan.id', '$.vulns']) END AS f
  FROM {source}
  WHERE contains(line, '"vulns"')
)
SELECT as_text(f[1]::VARCHAR, '_shodan.id') AS rec_id, f[2] AS vulns
FROM records WHERE f[2] IS NOT NULL
"""


def _entries_sql(raw: Path) -> str:
    """One row per record x CVE from pass 2's file: rec_id, cve, and the entry as a map."""
    return f"""
SELECT rec_id, e.key AS cve, jmap(e.value, 'vulns.*') AS v
FROM (SELECT rec_id, unnest(map_entries(jmap(vulns, 'vulns'))) AS e
      FROM read_parquet('{raw}'))
"""


def vuln_sql(raw: Path) -> str:
    """Query for bronze.vuln: the per-record fields of every CVE entry, no description text."""
    typed = []
    for name, kind in VULN_FIELDS:
        value = "v['" + name + "']"
        typed.append(f"{_cast(value, f'vulns.*.{name}', kind)} AS {name}")
    known = {name for name, _ in VULN_FIELDS + CVE_TEXT_FIELDS}
    unknown = _unknown_entries("v", known, "vulns.*")
    return f"""
SELECT rec_id, cve,
  {",\n  ".join(typed)},
  CASE WHEN len({unknown}) > 0 THEN map_from_entries({unknown}) END AS extra
FROM ({_entries_sql(raw)})
"""


def cve_text_sql(raw: Path) -> str:
    """Query for bronze.cve_text: each distinct (cve, summary, references) once.

    Grouping on a hash of the text, not the text itself, keeps the aggregate small: the
    full file has 39.2 GB of this text across 20,988,468 entries but only 11,064 CVEs.
    """
    return f"""
SELECT cve,
  any_value(as_text(v['summary'], 'vulns.*.summary')) AS summary,
  any_value(as_list(v['references'], 'vulns.*.references')) AS "references"
FROM ({_entries_sql(raw)})
GROUP BY cve, md5(coalesce(v['summary']::VARCHAR, '')), md5(coalesce(v['references']::VARCHAR, ''))
"""


def _copy(con: duckdb.DuckDBPyConnection, query: str, target: Path, options: str = "") -> None:
    """Write a query's result to Parquet."""
    con.execute(f"COPY ({query}) TO '{target}' (FORMAT PARQUET, COMPRESSION ZSTD{options})")


def _record_pass(con: duckdb.DuckDBPyConnection, manifest: Manifest, staging: Path) -> None:
    """Pass 1: stream the source once into banner, one row per line."""
    (staging / "banner").mkdir()
    _copy(
        con,
        record_pass_sql(_source_sql(manifest)),
        staging / "banner" / "data.parquet",
        ", ROW_GROUP_SIZE 100000",
    )


def _cve_pass(con: duckdb.DuckDBPyConnection, manifest: Manifest, staging: Path) -> None:
    """Pass 2: stream the source again for CVE entries; split them into vuln and cve_text.

    The stream only copies each record's `vulns` JSON as it is. Unpacking it into one row
    per CVE happens afterwards, from Parquet: unpacking while streaming ran out of memory
    (19 GiB) on the full file, where one record can list a thousand CVEs.
    """
    raw = staging / "vulns_raw.parquet"
    # Rows here are large (a record's vulns JSON averages 90 KB), so row groups are kept to
    # DuckDB's minimum of 2,048 rows.
    _copy(con, cve_pass_sql(_source_sql(manifest)), raw, ", ROW_GROUP_SIZE 2048")
    for table in ("vuln", "cve_text"):
        (staging / table).mkdir()
    _copy(con, vuln_sql(raw), staging / "vuln" / "data.parquet")
    _copy(con, cve_text_sql(raw), staging / "cve_text" / "data.parquet")
    raw.unlink()


def _checks(
    con: duckdb.DuckDBPyConnection,
    staging: Path,
    manifest: Manifest,
    rows: dict[str, int],
    max_empty_share: float,
) -> tuple[list[Check], dict[str, int]]:
    """Run the bronze checks; also return every unknown key with how often it appeared."""

    def read(table: str) -> str:
        return f"read_parquet('{staging / table}/*.parquet', hive_partitioning=false)"

    def one(sql: str) -> tuple[int, ...]:
        row = con.execute(sql).fetchone()
        assert row is not None
        return tuple(int(x or 0) for x in row)

    readable, missing_id, dup_id, empty, cve_entries = one(
        f"SELECT count(*), count(*) FILTER (WHERE rec_id IS NULL), "
        f"count(rec_id) - count(DISTINCT rec_id), "
        f"count(*) FILTER (WHERE ip IS NULL OR ts IS NULL), sum(len(cves)) "
        f"FROM {read('banner')} WHERE parse_error IS NULL"
    )
    rows["unreadable"] = rows["banner"] - readable
    (cves,) = one(f"SELECT count(DISTINCT cve) FROM {read('cve_text')}")
    unknown = dict(
        con.execute(
            f"SELECT k, count(*) FROM ("
            f"  SELECT unnest(map_keys(extra)) AS k FROM {read('banner')} WHERE extra IS NOT NULL"
            f"  UNION ALL"
            f"  SELECT unnest(map_keys(extra)) FROM {read('vuln')} WHERE extra IS NOT NULL"
            f") GROUP BY k ORDER BY 2 DESC"
        ).fetchall()
    )
    share = empty / readable if readable else 1.0
    checks = [
        Check(
            name="reconciliation",
            blocking=True,
            passed=rows["banner"] == manifest.lines,
            detail=f"banner {rows['banner']} rows ({rows['unreadable']} unreadable); "
            f"landing counted {manifest.lines} lines",
        ),
        Check(
            name="rec_id_unique",
            blocking=True,
            passed=missing_id == 0 and dup_id == 0,
            detail=f"{missing_id} missing, {dup_id} duplicated",
        ),
        Check(
            name="empty_ip_or_ts",
            blocking=True,
            passed=share <= max_empty_share,
            detail=f"{empty} rows ({share:.4%}); limit {max_empty_share:.2%}",
        ),
        Check(
            name="cve_reconciliation",
            blocking=True,
            passed=rows["vuln"] == cve_entries,
            detail=f"vuln {rows['vuln']} rows; banner lists {cve_entries} CVE entries",
        ),
        Check(
            name="cve_text_one_version",
            blocking=False,
            passed=rows["cve_text"] == cves,
            detail=f"{rows['cve_text']} text rows for {cves} CVEs",
        ),
        Check(
            name="unknown_keys",
            blocking=False,
            passed=not unknown,
            detail=", ".join(f"{k} ({n})" for k, n in unknown.items()) or "none",
        ),
    ]
    return checks, unknown


def _publish(staging: Path, data_root: Path, file_id: str) -> None:
    """Move each staged table into its file_id partition, replacing any earlier copy."""
    for table in TABLES:
        final = data_root / "bronze" / table / f"file_id={file_id}"
        shutil.rmtree(final, ignore_errors=True)
        final.parent.mkdir(parents=True, exist_ok=True)
        (staging / table).rename(final)


def _dir_bytes(path: Path) -> int:
    """Total size of the files under a folder; 0 if it does not exist."""
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.exists() else 0


def _process_peak_gb() -> float:
    """Highest memory this process has used so far, across all steps."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is in bytes on macOS and in kilobytes on Linux.
    return peak / 1e9 if sys.platform == "darwin" else peak / 1e6


@contextmanager
def _watched(con: duckdb.DuckDBPyConnection, step: str, spill: Path, log: RunLog) -> Iterator[None]:
    """Time a step and sample DuckDB memory and spill size while it runs.

    A sample is logged every SAMPLE_SECONDS and the step's peaks go into the run log, so
    a slow or failing step shows where its memory went instead of failing silently.
    """
    probe = con.cursor()
    peaks = {"duckdb_gb": 0.0, "spill_gb": 0.0}
    stop = threading.Event()
    started = time.time()

    def sample() -> None:
        while not stop.wait(SAMPLE_SECONDS):
            by_tag = probe.execute(
                "SELECT tag, memory_usage_bytes FROM duckdb_memory() ORDER BY 2 DESC"
            ).fetchall()
            duckdb_gb = sum(b for _, b in by_tag) / 1e9
            spill_gb = _dir_bytes(spill) / 1e9
            peaks["duckdb_gb"] = max(peaks["duckdb_gb"], duckdb_gb)
            peaks["spill_gb"] = max(peaks["spill_gb"], spill_gb)
            top = ", ".join(f"{tag} {b / 1e9:.1f}" for tag, b in by_tag[:3] if b)
            logger.info(
                "%s %4.0fs: duckdb %.1f GB [%s], spill %.1f GB, process peak %.1f GB",
                step,
                time.time() - started,
                duckdb_gb,
                top,
                spill_gb,
                _process_peak_gb(),
            )

    sampler = threading.Thread(target=sample, daemon=True)
    logger.info("%s started", step)
    sampler.start()
    try:
        yield
    finally:
        stop.set()
        sampler.join()
        probe.close()
        log.seconds[step] = time.time() - started
        log.peaks[step] = {**peaks, "process_peak_gb": _process_peak_gb()}
        logger.info("%s ended after %.1fs; peaks %s", step, log.seconds[step], log.peaks[step])


Step = Callable[[duckdb.DuckDBPyConnection, Manifest, Path], None]
STEPS: list[tuple[str, Step, tuple[str, ...]]] = [
    ("record_pass", _record_pass, ("banner",)),
    ("cve_pass", _cve_pass, ("vuln", "cve_text")),
]
STEP_NAMES = [name for name, _, _ in STEPS]


def build(
    manifest: Manifest, data_root: Path, max_empty_share: float, start_at: str = "record_pass"
) -> RunLog:
    """Write the bronze tables for one landed file, check them, then publish.

    Everything is written to a staging folder first. Published partitions change only when
    every blocking check passes, so a failed run never leaves half a file in bronze. A failed
    run keeps the outputs of the steps that finished, so `start_at` can resume from the step
    that failed instead of re-reading the whole file.
    """
    log = RunLog(
        run_id=uuid.uuid4().hex,
        step="bronze",
        file_id=manifest.file_id,
        started_at=datetime.now(UTC),
        resumed_from=None if start_at == STEP_NAMES[0] else start_at,
    )
    log.seconds["landing"] = manifest.landing_seconds
    staging = data_root / "_staging" / manifest.file_id
    spill = staging / "_spill"
    first = STEP_NAMES.index(start_at)
    if first == 0:
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    for _, _, tables in STEPS[:first]:
        missing = [t for t in tables if not (staging / t).exists()]
        if missing:
            _finish(log, manifest, data_root, error=f"cannot resume at {start_at}: no {missing}")
            return log

    con = duckdb.connect()
    con.execute("SET preserve_insertion_order = false")
    con.execute(f"SET threads = {THREADS}")
    con.execute(f"SET temp_directory = '{spill}'")
    con.execute(MACROS)
    current = start_at
    try:
        for name, run, tables in STEPS[first:]:
            current = name
            for table in tables:
                shutil.rmtree(staging / table, ignore_errors=True)
            with _watched(con, name, spill, log):
                run(con, manifest, staging)

        current = "checks"
        started = time.time()
        for table in TABLES:
            n = con.execute(
                f"SELECT count(*) FROM read_parquet('{staging / table}/*.parquet', "
                "hive_partitioning=false)"
            ).fetchone()
            log.rows[table] = n[0] if n else 0
        log.checks, unknown = _checks(con, staging, manifest, log.rows, max_empty_share)
        log.seconds["checks"] = time.time() - started
    except duckdb.Error as e:
        _finish(log, manifest, data_root, error=f"{current}: {e}")
        if current in STEP_NAMES:
            logger.error("staging kept; resume with --from %s", current)
        return log
    finally:
        con.close()
        shutil.rmtree(spill, ignore_errors=True)

    failed = [c for c in log.checks if c.blocking and not c.passed]
    if failed:
        _finish(log, manifest, data_root, error="; ".join(f"{c.name}: {c.detail}" for c in failed))
        logger.error("checks failed; staging kept at %s for inspection", staging)
        return log

    _publish(staging, data_root, manifest.file_id)
    shutil.rmtree(staging, ignore_errors=True)
    manifest.records = log.rows["banner"] - log.rows["unreadable"]
    manifest.unreadable = log.rows["unreadable"]
    manifest.unknown_keys = unknown
    _finish(log, manifest, data_root, error=None)
    return log


def _finish(log: RunLog, manifest: Manifest, data_root: Path, error: str | None) -> None:
    """Record the outcome in the file's manifest and in this run's log."""
    manifest.status = Status.FAILED if error else Status.BRONZE
    manifest.error = error
    log.finished_at = datetime.now(UTC)
    write_json(manifest_path(data_root, manifest.file_id), manifest)
    write_json(data_root / "_meta" / "run" / f"{log.run_id}.json", log)
