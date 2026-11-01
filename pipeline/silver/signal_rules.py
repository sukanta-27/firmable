"""The security findings silver looks for in each reply, one rule per `signal_code`.

Every expression is SQL over one `bronze_banner` row, plus four names the signal step
provides: `ip_ports` (distinct port/transport pairs on the address), `service_sightings`
(times the service was seen), `mac_ips` (distinct IPs carrying this record's Lantronix MAC)
and `module_list_ips` (distinct IPs carrying this record's exact rsync module list).

Rules match on what the reply contains, never on the scanner's probe name. Honeypot, CDN and
answers-everything services never reach these rules, so none repeats that filter. Thresholds
live here rather than in settings: changing one changes what a stored code means, which needs
a new code ending `_v2`.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """`evidence_field` and `evidence` are SQL too; `evidence` is built NULL-safe, because one
    NULL inside `||` blanks the whole excerpt."""

    predicate: str
    evidence_field: str
    evidence: str


OPTS_VULNS = "json_extract_string(opts, '$.vulns[*]')"
ICS_OBJECTS = ["siemens_s7", "bacnet", "ethernetip", "codesys", "knx", "pcworx", "mitsubishi_q"]
AI_OBJECTS = ["ollama", "llama_cpp", "localai", "comfyui", "anything_llm"]
# Names only: MongoDB 4.4+ serverStatus always has oldestRequiredTimestampForCrashRecovery,
# and Elasticsearch index stats contain "recovery". Evidence repeats these conditions, so the
# excerpt comes from the part that matched, not from whichever object the record carries.
MONGO_NAMES = "json_extract_string(mongodb, '$.listDatabases.databases[*].name')"
ELASTIC_NAMES = "json_keys(json_extract(elastic, '$.indices'))"
RANSOM_DB_NAME = "upper(n) LIKE '%RECOVER%' OR upper(n) LIKE 'README%' OR upper(n) LIKE 'READ_ME%'"
RANSOM_INDEX_NAME = "lower(n) IN ('read_me', 'readme', 'read-me') OR lower(n) LIKE '%meow%'"
RANSOM_MONGO = f"len(list_filter({MONGO_NAMES}, lambda n: {RANSOM_DB_NAME})) > 0"
RANSOM_ELASTIC = f"len(list_filter({ELASTIC_NAMES}, lambda n: {RANSOM_INDEX_NAME})) > 0"
RANSOM_NOTE = (
    "recover your (files|data|database)[^.]{0,40}(send|pay)[^.]{0,20}[0-9.]+ ?(btc|bitcoin)"
)
RANSOM_IN_DATA = f"regexp_matches(lower(coalesce(data, '')), '{RANSOM_NOTE}')"
RANSOM_PAGE = (
    f"({RANSOM_IN_DATA} OR regexp_matches(lower(coalesce(http_html, '')), '{RANSOM_NOTE}'))"
)


def _present(objects: list[str]) -> str:
    return f"array_to_string(list_filter(proto_keys, lambda k: list_contains({objects}, k)), ',')"


RULES: dict[str, Rule] = {
    # Real risk
    "heartbleed_vulnerable": Rule(
        # The leaked memory echoes the scanner's own heartbeat payload: proof, not a version
        # guess. All 160 VULNERABLE results on the 2026-10-26 file contain it.
        "json_extract_string(opts, '$.heartbleed') LIKE '% - VULNERABLE%'"
        " AND contains(json_extract_string(opts, '$.heartbleed'), 'census.shodan')",
        "'opts.heartbleed'",
        "json_extract_string(opts, '$.heartbleed')",
    ),
    "tag_compromised": Rule(
        "list_contains(tags, 'compromised')",
        "'tags'",
        "concat_ws(' | ', array_to_string(tags, ','), http_title, left(data, 200))",
    ),
    "ransom_note": Rule(
        f"{RANSOM_MONGO} OR {RANSOM_ELASTIC} OR {RANSOM_PAGE}",
        f"CASE WHEN {RANSOM_MONGO} THEN 'mongodb.listDatabases'"
        f" WHEN {RANSOM_ELASTIC} THEN 'elastic.indices'"
        f" WHEN {RANSOM_IN_DATA} THEN 'data' ELSE 'http_html' END",
        f"CASE WHEN {RANSOM_MONGO} THEN 'databases: ' || array_to_string(list_filter("
        f"{MONGO_NAMES}, lambda n: {RANSOM_DB_NAME}), ',')"
        f" WHEN {RANSOM_ELASTIC} THEN 'indices: ' || array_to_string(list_filter("
        f"{ELASTIC_NAMES}, lambda n: {RANSOM_INDEX_NAME}), ',')"
        f" ELSE regexp_extract(regexp_replace(CASE WHEN {RANSOM_IN_DATA} THEN data"
        " ELSE http_html END, '\\s+', ' ', 'g'), '(?i)recover your.{0,200}', 0) END",
    ),
    "mongodb_noauth": Rule(
        "json_extract_string(mongodb, '$.authentication') = 'false'",
        "'mongodb'",
        "concat_ws(' | ', 'databases: ' || array_to_string("
        "json_extract_string(mongodb, '$.listDatabases.databases[*].name'), ','),"
        " CAST(mongodb AS VARCHAR))",
    ),
    "redis_noauth": Rule(
        "json_extract(redis, '$.server') IS NOT NULL"
        " OR json_extract(redis, '$.keyspace') IS NOT NULL",
        "'redis'",
        "concat_ws(' | ', 'keyspace: ' || CAST(json_extract(redis, '$.keyspace') AS VARCHAR),"
        " CAST(redis AS VARCHAR))",
    ),
    "elastic_indices": Rule(
        "json_extract(elastic, '$.indices') IS NOT NULL",
        "'elastic.indices'",
        "'indices: ' || array_to_string(json_keys(json_extract(elastic, '$.indices')), ',')",
    ),
    "docker_registry_open": Rule(
        "json_extract(docker_registry, '$.repositories') IS NOT NULL",
        "'docker_registry.repositories'",
        "CAST(json_extract(docker_registry, '$.repositories') AS VARCHAR)",
    ),
    "ftp_anonymous": Rule(
        # The anonymous flag alone is the scanner's attempt; the 230 line is the server
        # accepting the login.
        "json_extract_string(ftp, '$.anonymous') = 'true'"
        " AND regexp_matches(data, '(^|\\n)230[ -]')",
        "'data'",
        "data",
    ),
    "smb_anonymous": Rule(
        # 201 of 450 anonymous SMB replies on the 2026-10-26 file list only IPC$ or nothing,
        # which exposes no files.
        "json_extract_string(smb, '$.anonymous') = 'true'"
        " AND list_contains(json_extract_string(smb, '$.shares[*].type'), 'Disk')",
        "'smb.shares'",
        "concat_ws(' | ', CAST(json_extract(smb, '$.shares') AS VARCHAR),"
        " 'os: ' || json_extract_string(smb, '$.os'))",
    ),
    "vnc_noauth": Rule(
        # FictusVNC is a VNC honeypot product.
        "json_extract(vnc, '$.security_types.\"1\"') IS NOT NULL"
        " AND product IS DISTINCT FROM 'FictusVNC'",
        "'vnc.security_types'",
        "concat_ws(' | ', CAST(json_extract(vnc, '$.security_types') AS VARCHAR), left(data, 160))",
    ),
    "lantronix_password": Rule(
        # A MAC on several IPs is a cloned template: one MAC with password `medu` sits on 13.
        "json_extract(lantronix, '$.password') IS NOT NULL AND mac_ips = 1",
        "'lantronix.password'",
        "CAST(lantronix AS VARCHAR)",
    ),
    "printer_no_password": Rule(
        "json_extract_string(hp_printer_embedded_web_server, '$.password_status') = 'notSet'",
        "'hp_printer_embedded_web_server.password_status'",
        "CAST(hp_printer_embedded_web_server AS VARCHAR)",
    ),
    "ai_llm_open": Rule(
        # Honeypot fleets answer as these APIs on many ports at once.
        "(ollama IS NOT NULL OR llama_cpp IS NOT NULL OR localai IS NOT NULL"
        " OR comfyui IS NOT NULL OR json_extract_string(anything_llm, '$.RequiresAuth') = 'false')"
        " AND ip_ports < 20",
        _present(AI_OBJECTS),
        "concat_ws(' | ', CAST(ollama AS VARCHAR), CAST(llama_cpp AS VARCHAR),"
        " CAST(localai AS VARCHAR), CAST(comfyui AS VARCHAR), CAST(anything_llm AS VARCHAR))",
    ),
    "ics_protocol": Rule(
        # S7 on addresses with 10+ ports carries templated `Plant_XXXX` ids, likely honeypots.
        f"({' OR '.join(f'{o} IS NOT NULL' for o in ICS_OBJECTS)}"
        " OR json_extract(opts, '$.modbus') IS NOT NULL) AND ip_ports < 10",
        f"coalesce(nullif({_present(ICS_OBJECTS)}, ''), 'opts.modbus')",
        f"CAST(coalesce({', '.join(ICS_OBJECTS)}, json_extract(opts, '$.modbus')) AS VARCHAR)",
    ),
    "tag_ssh_bad_key": Rule(
        "list_contains(tags, 'ssh-bad-key')",
        "'tags'",
        "concat_ws(' | ', 'ssh-bad-key', ssh_fingerprint, left(data, 160))",
    ),
    # Potential risk
    "opts_vuln_tilde": Rule(
        f"len(list_filter({OPTS_VULNS}, lambda x: x LIKE '~%')) > 0",
        "'opts.vulns'",
        f"concat_ws(' | ', array_to_string({OPTS_VULNS}, ','), http_title, left(data, 120))",
    ),
    "atg_inventory": Rule(
        # Only 4 of 12 replies read on the 2026-10-26 file were real gauges.
        "contains(data, 'I20100')",
        "'data'",
        "data",
    ),
    "rsync_noauth": Rule(
        # One lure list ("Public data mirror / Daily backup snapshots") repeats on 5 IPs; the
        # cut-off of 5 is assumed from that one list.
        "json_extract_string(rsync, '$.authentication') = 'false'"
        " AND CAST(json_extract(rsync, '$.modules') AS VARCHAR) IS DISTINCT FROM '{}'"
        " AND json_extract(rsync, '$.modules') IS NOT NULL AND module_list_ips < 5",
        "'rsync.modules'",
        "CAST(json_extract(rsync, '$.modules') AS VARCHAR)",
    ),
    "ipmi_exposed": Rule("ipmi IS NOT NULL", "'ipmi'", "CAST(ipmi AS VARCHAR)"),
    "esxi_exposed": Rule(
        "vmware IS NOT NULL",
        "'vmware'",
        "coalesce(json_extract_string(vmware, '$.full_name'), CAST(vmware AS VARCHAR))",
    ),
    "ntp_monlist": Rule(
        "json_type(json_extract(ntp, '$.monlist')) = 'OBJECT'",
        "'ntp.monlist'",
        "CAST(json_extract(ntp, '$.monlist') AS VARCHAR)",
    ),
    "dns_open_resolver": Rule(
        # Public anycast resolvers are open on purpose and re-scanned constantly: 8.8.8.8
        # alone is 912 records.
        "json_extract_string(dns, '$.recursive') = 'true' AND service_sightings <= 5",
        "'dns.recursive'",
        "concat_ws(' | ', CAST(dns AS VARCHAR), left(data, 100))",
    ),
    "snmp_v1_v2": Rule(
        # A v1 reply with the system description means the community string was accepted.
        "list_contains(CAST(json_extract(snmp, '$.versions') AS INT[]), 1)"
        " AND (json_extract(snmp, '$.description') IS NOT NULL"
        " OR json_extract(snmp, '$.name') IS NOT NULL)",
        "'snmp'",
        "CAST(snmp AS VARCHAR)",
    ),
    "rdp_exposed": Rule(
        "rdp_encryption IS NOT NULL OR product = 'Remote Desktop Protocol'",
        "CASE WHEN rdp_encryption IS NOT NULL THEN 'rdp_encryption' ELSE 'product' END",
        "concat_ws(' | ', product, version, CAST(rdp_encryption AS VARCHAR), left(data, 150))",
    ),
    "rdp_standard_security": Rule(
        "list_contains(json_extract_string(rdp_encryption, '$.protocols[*]'),"
        " 'Standard RDP Security')",
        "'rdp_encryption.protocols'",
        "CAST(rdp_encryption AS VARCHAR)",
    ),
    "smb_v1": Rule(
        "json_extract_string(smb, '$.smb_version') = '1'",
        "'smb.smb_version'",
        "concat_ws(' | ', 'SMBv1', json_extract_string(smb, '$.software'), left(data, 200))",
    ),
    "telnet_object": Rule(
        # No exclusion for SSH or VNC banners: 0 of 4,446 telnet objects on the 2026-10-26 file
        # sit on one. The SSH replies come from the probe named telnet, not the object.
        "telnet IS NOT NULL",
        "'telnet'",
        "concat_ws(' | ', product, version, left(data, 220), CAST(telnet AS VARCHAR))",
    ),
    "node_exporter_open": Rule(
        "node_exporter IS NOT NULL",
        "'node_exporter'",
        "CAST(coalesce(json_extract(node_exporter, '$.node_uname_info'), node_exporter)"
        " AS VARCHAR)",
    ),
    "http_dir_listing": Rule(
        "http_title LIKE 'Index of /%' OR open_dir IS NOT NULL OR list_contains(tags, 'open-dir')",
        "CASE WHEN open_dir IS NOT NULL THEN 'open_dir' WHEN http_title LIKE 'Index of /%'"
        " THEN 'http_title' ELSE 'tags' END",
        "concat_ws(' | ', http_title, CAST(open_dir AS VARCHAR),"
        " left(regexp_replace(http_html, '\\s+', ' ', 'g'), 220),"
        " CASE WHEN list_contains(tags, 'open-dir') THEN 'open-dir' END)",
    ),
    "tag_database": Rule(
        # 4,344 of 15,455 database-tagged replies on the 2026-10-26 file refuse the scanner's
        # host, so nothing is open to it.
        "list_contains(tags, 'database')"
        " AND coalesce(json_extract_string(mysql, '$.error_code'), '') NOT IN ('1130', '1129')"
        " AND NOT contains(coalesce(data, ''), 'no pg_hba.conf entry')"
        " AND NOT contains(coalesce(data, ''), 'not allowed to connect')",
        "'tags'",
        "concat_ws(' | ', array_to_string(proto_keys, ','), product, left(data, 220))",
    ),
    "tag_medical": Rule(
        "list_contains(tags, 'medical')",
        "'tags'",
        "concat_ws(' | ', 'medical', product, left(data, 220))",
    ),
    "tls_sslv2_sslv3": Rule(
        "list_has_any(tls_versions, ['SSLv2', 'SSLv3'])",
        "'tls_versions'",
        "concat_ws(' | ', array_to_string(tls_versions, ','), tls_cipher_name)",
    ),
    "tls_weak_key": Rule(
        "(cert_pubkey_type = 'rsa' AND cert_pubkey_bits < 2048) OR cert_sig_alg ILIKE '%md5%'",
        "CASE WHEN cert_sig_alg ILIKE '%md5%' THEN 'cert_sig_alg' ELSE 'cert_pubkey_bits' END",
        "concat_ws(' | ', cert_pubkey_type || ' ' || cert_pubkey_bits, cert_sig_alg,"
        " CAST(cert_subject AS VARCHAR))",
    ),
    "tag_eol_os": Rule(
        "list_contains(tags, 'eol-os')",
        "'tags'",
        "concat_ws(' | ', 'eol-os', os, array_to_string(cpe23, ','), left(data, 160))",
    ),
}

# What each rule checks, in plain words, for the finding-score prompt. Kept free of counts,
# exploit lists and our own risk split: the prompt is answered blind and checked against those.
DESCRIPTIONS: dict[str, str] = {
    "heartbleed_vulnerable": "A TLS service answered a Heartbleed test (CVE-2014-0160) in a way "
    "that shows it leaks the contents of its memory.",
    "tag_compromised": "The scanner marked the host as compromised: its reply shows signs that "
    "an attacker already controls it.",
    "ransom_note": "A database or search index is named like a ransom note, or a web page asks "
    "for bitcoin to recover files: someone has already wiped or encrypted data and left a demand.",
    "mongodb_noauth": "A MongoDB database answers queries without asking for a login.",
    "redis_noauth": "A Redis data store answers commands and shows its data without a password.",
    "elastic_indices": "An Elasticsearch server lists its data indices to anyone, without a login.",
    "docker_registry_open": "A Docker image registry lists its stored images to anyone, without "
    "a login.",
    "ftp_anonymous": "An FTP file server accepted an anonymous login.",
    "smb_anonymous": "A Windows file-sharing (SMB) server lets anyone list at least one disk "
    "share without a login.",
    "vnc_noauth": "A VNC remote-desktop server offers access with no password.",
    "lantronix_password": "A Lantronix device server (a serial-to-network adapter) reveals its "
    "admin password in its reply.",
    "printer_no_password": "An HP printer's web admin page has no admin password set.",
    "ai_llm_open": "A self-hosted AI model server (Ollama, llama.cpp, LocalAI, ComfyUI or "
    "AnythingLLM) accepts requests without a login.",
    "ics_protocol": "An industrial control system (Siemens S7, BACnet, EtherNet/IP, CODESYS, "
    "KNX, PCWorx, MELSEC or Modbus) answers control-protocol requests from the internet.",
    "tag_ssh_bad_key": "An SSH server uses a host key that is publicly known (shipped as a "
    "default or leaked), so its connections can be impersonated or decrypted.",
    "opts_vuln_tilde": "The scanner listed a vulnerability for this service as possible but "
    "unconfirmed, inferred from the software version.",
    "atg_inventory": "A fuel-tank gauge (automatic tank gauge) answers inventory commands from the "
    "internet, showing tank contents and levels.",
    "rsync_noauth": "An rsync file-sync server lists its shared folders without a login.",
    "ipmi_exposed": "A server's out-of-band management controller (IPMI) is reachable from the "
    "internet.",
    "esxi_exposed": "A VMware ESXi or vCenter virtualisation management service is reachable from "
    "the internet.",
    "ntp_monlist": "An NTP time server answers the 'monlist' command, which returns a list of its "
    "recent clients and a reply much larger than the request.",
    "dns_open_resolver": "A DNS server answers recursive lookups for anyone on the internet.",
    "snmp_v1_v2": "An SNMP v1 or v2 network-management service returned the device's description "
    "or name to a community string (a shared password, often a default).",
    "rdp_exposed": "A Windows Remote Desktop (RDP) login is reachable from the internet.",
    "rdp_standard_security": "A Windows Remote Desktop server accepts its legacy 'Standard RDP "
    "Security' mode instead of requiring TLS with network-level authentication.",
    "smb_v1": "A Windows file-sharing server speaks SMB version 1, the original protocol version.",
    "telnet_object": "A Telnet service (an unencrypted remote login) is reachable from the "
    "internet.",
    "node_exporter_open": "A Prometheus node exporter publishes the machine's system metrics to "
    "anyone.",
    "http_dir_listing": "A web server shows a listing of the files in a directory.",
    "tag_database": "A database server (such as MySQL, PostgreSQL or SQL Server) is reachable from "
    "the internet and answered the scanner rather than refusing it.",
    "tag_medical": "A medical imaging system (DICOM) accepted a connection from the internet.",
    "tls_sslv2_sslv3": "The service still accepts the obsolete SSLv2 or SSLv3 encryption "
    "protocols.",
    "tls_weak_key": "The service's certificate uses an RSA key under 2048 bits or an MD5 "
    "signature.",
    "tag_eol_os": "The scanner identified the operating system as end-of-life: it no longer gets "
    "security updates.",
}
