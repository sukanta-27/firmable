"""Step 3, tighten and re-measure: for each signal whose raw replies showed false matches,
the count before and after the tightened rule, plus the measurements behind each rule.
Run: uv run python archive/blind-analysis/scripts/07_tighten.py sample|full
"""

from _db import ROOT, connect, show

con, ds = connect()
stats = ROOT / "archive" / "blind-analysis" / "cache" / f"ip_stats.{ds}.parquet"
con.execute(f"CREATE TEMP VIEW s AS SELECT * FROM '{stats}'")
con.execute(
    "CREATE TEMP VIEW b AS SELECT banner.*, s.ip_ports, coalesce(s.ip_honeypot, false) AS hp_ip "
    "FROM banner LEFT JOIN s USING (ip)"
)
print(f"dataset={ds}")


def before_after(title: str, base: str, tight: str) -> None:
    show(
        con,
        f"""SELECT count(*) FILTER (WHERE {base}) AS before_records,
              count(DISTINCT ip) FILTER (WHERE {base}) AS before_ips,
              count(*) FILTER (WHERE ({base}) AND ({tight})) AS after_records,
              count(DISTINCT ip) FILTER (WHERE ({base}) AND ({tight})) AS after_ips
            FROM b WHERE {base}""",
        title,
    )


# BlueKeep: Microsoft lists only Windows XP/2003/Vista/7/2008/2008 R2 as affected
# (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708).
BK = "rec_id IN (SELECT rec_id FROM vuln WHERE verified AND cve = 'CVE-2019-0708')"
show(
    con,
    f"""SELECT CASE WHEN version IS NULL THEN 'no build reported'
                    WHEN version LIKE '5.%' OR version LIKE '6.0.%' OR version LIKE '6.1.%'
                      THEN 'affected family (<= 6.1)'
                    ELSE 'build Microsoft lists as not affected (>= 6.2)' END AS build,
              count(*) AS records
        FROM b WHERE {BK} GROUP BY 1 ORDER BY 2 DESC""",
    "T1. BlueKeep verified records by reported Windows build",
)
before_after(
    "T1b. BlueKeep verified, excluding builds >= 6.2",
    BK,
    "version IS NULL OR version LIKE '5.%' OR version LIKE '6.0.%' OR version LIKE '6.1.%'",
)

# Ghostcat appears only in opts.vulns; most replies carry the same fake header.
GC = "list_contains(json_extract_string(opts, '$.vulns[*]'), 'CVE-2020-1938')"
before_after(
    "T2. Ghostcat (opts only): AJP port 8009, no X-Confluence-Request-Time, not honeypot",
    GC,
    "port = 8009 AND NOT contains(data, 'X-Confluence-Request-Time') AND NOT hp_ip",
)
show(
    con,
    """SELECT contains(data, 'X-Confluence-Request-Time') AS fake_confluence_header,
              hp_ip, ip_ports >= 20 AS ip_20plus_ports, count(*) AS records
        FROM b WHERE contains(data, 'X-Confluence-Request-Time') GROUP BY ALL ORDER BY ALL""",
    "T2b. every record with the X-Confluence-Request-Time header, by honeypot tag and ports",
)

# Heartbleed proof: the reply hexdump contains the scanner's own heartbeat payload.
HB = "json_extract_string(opts, '$.heartbleed') LIKE '% - VULNERABLE%'"
before_after(
    "T3. Heartbleed VULNERABLE whose dump echoes the scanner payload 'census.shodan'",
    HB,
    "contains(json_extract_string(opts, '$.heartbleed'), 'census.shodan')",
)

# FREAK/Logjam: does the reply show weak DH?
show(
    con,
    """SELECT json_extract_string(tls_dhparams, '$.bits') AS dh_bits,
              json_extract_string(tls_dhparams, '$.fingerprint') AS dh_known_prime,
              count(*) AS records
        FROM b WHERE rec_id IN (SELECT rec_id FROM vuln WHERE verified
                                AND cve IN ('CVE-2015-0204', 'CVE-2015-4000'))
        GROUP BY ALL ORDER BY records DESC LIMIT 10""",
    "T4. FREAK/Logjam verified records: DH params the reply shows",
)

# SMB anonymous: IPC$ only exposes nothing to read.
SA = "json_extract_string(smb, '$.anonymous') = 'true'"
before_after(
    "T5. SMB anonymous with at least one Disk share listed",
    SA,
    "list_contains(json_extract_string(smb, '$.shares[*].type'), 'Disk')",
)

# rsync: authentication=false with no modules exposes nothing.
RS = "json_extract_string(rsync, '$.authentication') = 'false'"
before_after(
    "T6. rsync no-auth with at least one module, not on a honeypot-tagged IP",
    RS,
    "json_extract(rsync, '$.modules') IS NOT NULL AND CAST(json_extract(rsync, '$.modules') "
    "AS VARCHAR) <> '{}' AND NOT hp_ip",
)
show(
    con,
    f"""SELECT left(CAST(json_extract(rsync, '$.modules') AS VARCHAR), 120) AS modules,
              count(DISTINCT ip) AS ips
        FROM b WHERE {RS} AND CAST(json_extract(rsync, '$.modules') AS VARCHAR) <> '{{}}'
        GROUP BY 1 ORDER BY 2 DESC LIMIT 8""",
    "T6b. rsync module lists repeated across IPs",
)

# Lantronix: a MAC address seen on several IPs is a cloned template, not a device.
LP = "json_extract(lantronix, '$.password') IS NOT NULL"
con.execute(
    f"""CREATE TEMP TABLE lmac AS SELECT json_extract_string(lantronix, '$.mac') AS mac,
           count(DISTINCT ip) AS ips FROM b WHERE {LP} GROUP BY 1"""
)
before_after(
    "T7. Lantronix password leak, MAC seen on one IP only and not honeypot",
    LP,
    "NOT hp_ip AND json_extract_string(lantronix, '$.mac') IN (SELECT mac FROM lmac WHERE ips = 1)",
)
show(
    con,
    f"""SELECT json_extract_string(lantronix, '$.password') AS password,
              json_extract_string(lantronix, '$.mac') AS mac, count(DISTINCT ip) AS ips
        FROM b WHERE {LP} GROUP BY ALL ORDER BY ips DESC LIMIT 6""",
    "T7b. Lantronix passwords by MAC",
)

# VNC no-auth: FictusVNC is a VNC honeypot product.
VN = "json_extract(vnc, '$.security_types.\"1\"') IS NOT NULL"
before_after(
    "T8. VNC security type None, excluding FictusVNC and honeypot IPs",
    VN,
    "coalesce(product, '') <> 'FictusVNC' AND NOT hp_ip",
)

# ICS: many-port hosting IPs serving S7 are likely honeypots.
ICS = (
    "siemens_s7 IS NOT NULL OR bacnet IS NOT NULL OR ethernetip IS NOT NULL OR codesys IS NOT"
    " NULL OR knx IS NOT NULL OR pcworx IS NOT NULL OR mitsubishi_q IS NOT NULL OR "
    "json_extract(opts, '$.modbus') IS NOT NULL"
)
before_after(
    "T9. ICS protocol reply, not honeypot, IP answers on < 10 ports",
    ICS,
    "NOT hp_ip AND ip_ports < 10",
)
show(
    con,
    """SELECT ip_ports >= 10 AS ip_10plus_ports, hp_ip,
              json_extract_string(siemens_s7, '$.identities."Plant identification".value')
                AS plant_id,
              count(*) AS records
        FROM b WHERE siemens_s7 IS NOT NULL GROUP BY ALL ORDER BY records DESC LIMIT 10""",
    "T9b. S7 replies by port count, honeypot tag, plant identification",
)

# Automated tank gauges answering the inventory command.
ATG = "probe = 'automated-tank-gauge'"
before_after(
    "T10. ATG probe -> reply is an I20100 inventory report",
    ATG,
    "contains(data, 'I20100') AND NOT hp_ip",
)

# InfluxDB: one uniform fleet.
IF = "json_extract(influxdb, '$.databases') IS NOT NULL"
before_after(
    "T11. InfluxDB databases listed, excluding the uniform fleet signature",
    IF,
    "NOT (json_extract_string(influxdb, '$.bind_address') = '127.0.0.1:8088' AND "
    "list_contains(json_extract_string(influxdb, '$.databases[*]'), 'go_metrics'))",
)

# MCP and AI endpoints: honeypot fleets on AWS.
MCP = "mcp IS NOT NULL"
before_after("T12. MCP server, not honeypot, < 20 ports", MCP, "NOT hp_ip AND ip_ports < 20")
AI = (
    "ollama IS NOT NULL OR llama_cpp IS NOT NULL OR localai IS NOT NULL OR comfyui IS NOT NULL "
    "OR json_extract_string(anything_llm, '$.RequiresAuth') = 'false'"
)
before_after("T13. open AI/LLM API, not honeypot, < 20 ports", AI, "NOT hp_ip AND ip_ports < 20")
show(
    con,
    """SELECT k AS ollama_model, count(DISTINCT ip) AS ips FROM (
          SELECT ip, unnest(json_keys(ollama)) AS k FROM b WHERE ollama IS NOT NULL)
        WHERE k LIKE '%:%/%' OR k LIKE 'cve-%' OR k LIKE '%trigger%'
        GROUP BY 1 ORDER BY 2 DESC LIMIT 12""",
    "T13b. Ollama model names that point at another host or a CVE",
)
show(
    con,
    """SELECT count(DISTINCT ip) AS ollama_ips,
          count(DISTINCT ip) FILTER (WHERE len(list_filter(json_keys(ollama),
            lambda k: k LIKE '%.%.%.%:%/%' OR k LIKE 'cve-%')) > 0) AS ips_with_foreign_models
        FROM b WHERE ollama IS NOT NULL""",
    "T13c. Ollama instances holding models pulled from a raw IP or named cve-*",
)

# DNS: public anycast resolvers are open on purpose; they are seen many times.
DNS = "json_extract_string(dns, '$.recursive') = 'true'"
con.execute(f"CREATE TEMP TABLE dns_ip AS SELECT ip, count(*) AS n FROM b WHERE {DNS} GROUP BY ip")
before_after(
    "T14. open resolver, IP seen <= 5 times (drops re-scanned public anycast resolvers)",
    DNS,
    "ip IN (SELECT ip FROM dns_ip WHERE n <= 5)",
)
show(
    con,
    "SELECT ip, n FROM dns_ip ORDER BY n DESC LIMIT 8",
    "T14b. open resolvers seen most often",
)

# SNMP: v1 answering with system description means the community string was accepted.
SN = "list_contains(CAST(json_extract(snmp, '$.versions') AS INT[]), 1) OR probe = 'snmp_v2'"
before_after(
    "T15. SNMP v1/v2 that returned sysDescr or sysName",
    SN,
    "json_extract(snmp, '$.description') IS NOT NULL OR json_extract(snmp, '$.name') IS NOT NULL",
)

# Database ports that refuse the scanner's host are not open databases.
DB = "list_contains(tags, 'database')"
before_after(
    "T16. database tag, excluding replies that refuse the scanner's host",
    DB,
    "NOT (coalesce(json_extract_string(mysql, '$.error_code'), '') IN ('1130', '1129') OR "
    "contains(coalesce(data, ''), 'no pg_hba.conf entry') OR "
    "contains(coalesce(data, ''), 'not allowed to connect'))",
)

# FTP anonymous: reply must contain a 230 login line.
FT = "json_extract_string(ftp, '$.anonymous') = 'true'"
before_after(
    "T17. FTP anonymous with a 230 line in the reply, not honeypot",
    FT,
    "regexp_matches(data, '(^|\\n)230[ -]') AND NOT hp_ip",
)

# compromised tag: how many replies show the compromise themselves? Match ransom markers on
# database and index *names* only: MongoDB 4.4+ serverStatus always contains the key
# oldestRequiredTimestampForCrashRecovery, and Elasticsearch index stats contain "recovery".
RANSOM_DB = (
    "(len(list_filter(json_extract_string(mongodb, '$.listDatabases.databases[*].name'),"
    " lambda n: upper(n) LIKE '%RECOVER%' OR upper(n) LIKE 'README%' OR upper(n) LIKE 'READ_ME%'))"
    " > 0 OR len(list_filter(json_keys(json_extract(elastic, '$.indices')),"
    " lambda n: lower(n) IN ('read_me', 'readme', 'read-me') OR lower(n) LIKE '%meow%')) > 0)"
)
RANSOM_PAGE = (
    "regexp_matches(lower(coalesce(data, '') || ' ' || coalesce(http_html, '')),"
    " 'recover your (files|data|database)[^.]{0,40}(send|pay)[^.]{0,20}[0-9.]+ ?(btc|bitcoin)')"
)
show(
    con,
    f"""SELECT CASE
          WHEN regexp_matches(lower(coalesce(http_title, '') || coalesce(http_html, '')),
               'hacked by|pwned|defaced') THEN 'defacement text in page'
          WHEN {RANSOM_DB} THEN 'ransom-note database/index name'
          WHEN redis IS NOT NULL THEN 'redis INFO readable (keys not shown)'
          ELSE 'not visible in kept fields' END AS evidence,
          count(*) AS records
        FROM b WHERE list_contains(tags, 'compromised') GROUP BY 1 ORDER BY 2 DESC""",
    "T18. compromised tag: what the reply itself shows",
)
show(
    con,
    f"""SELECT CASE WHEN mongodb IS NOT NULL THEN 'mongodb' WHEN elastic IS NOT NULL
                    THEN 'elastic' ELSE 'http' END AS service,
              list_contains(tags, 'compromised') AS tagged_compromised,
              count(*) AS records, count(DISTINCT ip) AS ips
        FROM b WHERE {RANSOM_DB} OR {RANSOM_PAGE} GROUP BY ALL ORDER BY ALL""",
    "T21. ransom markers across the whole file, by service and compromised tag",
)
show(
    con,
    f"""SELECT ip, port,
          CASE WHEN mongodb IS NOT NULL THEN array_to_string(list_filter(
                 json_extract_string(mongodb, '$.listDatabases.databases[*].name'),
                 lambda n: upper(n) LIKE '%RECOVER%'), ',') || ' collections=' ||
                 coalesce(CAST(json_extract(mongodb, '$.listDatabases.databases[0].collections')
                   AS VARCHAR), '')
               WHEN elastic IS NOT NULL THEN 'index read_me docs=' ||
                 coalesce(json_extract_string(elastic, '$.indices.read_me.total.docs.count'), '?')
                 || ' of ' || json_array_length(json_keys(json_extract(elastic, '$.indices')))
                 || ' indices'
               ELSE regexp_extract(regexp_replace(
                   coalesce(data, '') || ' ' || coalesce(http_html, ''), '\\s+', ' ', 'g'),
                 'to recover your.{{0,200}}', 0) END AS what_the_reply_shows
        FROM b WHERE {RANSOM_DB} OR {RANSOM_PAGE} ORDER BY md5(rec_id)""",
    "T21b. every ransom-marker record",
)

# MySQL/PostgreSQL refusals: the scanner's own address appears in 224.0.0.0/4.
show(
    con,
    r"""SELECT regexp_extract(data, 'Host .(\d+)\.\d+\.\d+\.\d+. is not allowed', 1) AS first_octet,
              count(*) AS records
        FROM b WHERE contains(coalesce(data, ''), 'is not allowed to connect')
        GROUP BY 1 ORDER BY 2 DESC LIMIT 5""",
    "T19. first octet of the client address echoed in MySQL refusals",
)
show(
    con,
    """SELECT ip, ip_ports, left(org, 30) AS org,
              regexp_replace(left(data, 140), '\\s+', ' ', 'g') AS reply
        FROM b WHERE probe = 'automated-tank-gauge' AND contains(data, 'I20100') AND NOT hp_ip
        ORDER BY md5(rec_id) LIMIT 12""",
    "T10b. 12 tightened ATG records, ORDER BY md5(rec_id)",
)
show(
    con,
    """WITH v AS (SELECT rec_id, cve FROM vuln WHERE verified),
    r AS (SELECT v.cve, b.*, row_number() OVER (PARTITION BY v.cve ORDER BY md5(b.rec_id)) AS rn
          FROM v JOIN b USING (rec_id)
          WHERE v.cve IN ('CVE-2020-0796', 'CVE-2015-0204', 'MS15-034', 'CVE-2018-18441',
                          'CVE-2022-32548', 'CVE-2024-23897', 'CVE-2023-23333', 'CVE-2017-7269',
                          'MS17-010', 'CVE-2014-0160'))
    SELECT cve, ip, port, coalesce(product, '') || ' ' || coalesce(version, '') AS product,
      CASE WHEN cve = 'CVE-2020-0796'
             THEN 'smb caps=' || CAST(json_extract(smb, '$.capabilities') AS VARCHAR)
           WHEN cve = 'CVE-2015-0204'
             THEN 'dh_bits=' || coalesce(json_extract_string(tls_dhparams, '$.bits'), 'none')
           WHEN cve = 'CVE-2018-18441' THEN left(CAST(ip_camera AS VARCHAR), 160)
           WHEN cve = 'CVE-2014-0160'
             THEN left(json_extract_string(opts, '$.heartbleed'), 160)
           ELSE regexp_replace(left(data, 120), '\\s+', ' ', 'g') END AS what_the_reply_shows
    FROM r WHERE rn <= 3 ORDER BY cve, rn""",
    "T20. verified CVEs: what the kept reply shows, 3 records per CVE",
)
show(
    con,
    """SELECT json_extract_string(influxdb, '$.version') AS version,
              left(CAST(json_extract(influxdb, '$.databases') AS VARCHAR), 110) AS dbs,
              count(*) AS records, count(DISTINCT asn) AS asns
        FROM b WHERE json_extract(influxdb, '$.databases') IS NOT NULL
        GROUP BY ALL ORDER BY records DESC LIMIT 8""",
    "T11b. InfluxDB version and database sets",
)
show(
    con,
    """SELECT regexp_replace(json_extract_string(influxdb, '$.network_hostname'), '[0-9]+', 'N',
                            'g') AS hostname_pattern, count(*) AS records
        FROM b WHERE influxdb IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 12""",
    "T11c. InfluxDB network_hostname patterns (digits replaced by N)",
)
