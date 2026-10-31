"""Step 1: the narrow table of sightings every later step reads instead of bronze's banner.

Reading the wide banner once, for only the columns silver needs, is what keeps the later
group-bys small: bronze ran out of memory whenever it parsed or read more than it used.
"""

from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings

# The key is md5 over "ip|port|transport|hostname", with a NULL hostname as ''. Only the last
# field is free text, and ip, port and transport can never contain '|', so no two services
# serialise alike. Changing this text changes every key, and keys must match across files.
SERVICE_KEY = "md5(ip || '|' || port || '|' || transport || '|' || coalesce(hostname, ''))"

# list_distinct also drops the NULLs left by absent fields.
NTLM_NAMES = """list_distinct([lower(json_extract_string(ntlm, '$.' || f))
  FOR f IN ['dns_forest_name', 'dns_domain_name', 'fqdn']])"""
# rootDomainNamingContext 'DC=hs,DC=uci,DC=edu' -> 'hs.uci.edu'; the full file also writes 'dc='.
LDAP_ROOT_DOMAIN = """nullif(array_to_string(list_transform(
  list_filter(string_split(json_extract_string(ldap, '$.rootDomainNamingContext'), ','),
    lambda p: upper(trim(split_part(p, '=', 1))) = 'DC'),
  lambda p: trim(split_part(p, '=', 2))), '.'), '')"""
LDAP_NAMES = f"""list_distinct([lower(json_extract_string(ldap, '$.dnsHostName')),
  lower({LDAP_ROOT_DOMAIN})])"""


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    (staging / "sightings").mkdir()
    stage.copy(
        con,
        f"""
        SELECT {SERVICE_KEY} AS service_key, *
        FROM (
          SELECT rec_id, ts AS seen_at, ip, ip_version, port::INTEGER AS port, transport,
            scan_hostname AS hostname, product, version, http_waf,
            -- tags is NULL on untagged records; list functions on NULL give NULL, not false
            coalesce(tags, []) AS tags, asn, org, isp, country_code, hostnames,
            {NTLM_NAMES} AS ntlm_names, {LDAP_NAMES} AS ldap_names
          FROM bronze_banner
          WHERE parse_error IS NULL
        )
        """,
        staging / "sightings" / "data.parquet",
    )
