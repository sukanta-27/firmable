"""Which company each non-noise service belongs to, and how sure we are.

A strategy reads only the views `silver_service`, `silver_address`, `silver_identity_evidence`
and `asdb_landlord`, so gold and the synthetic eval feed it the same way.
"""

from collections.abc import Callable
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings

type Attributor = Callable[[duckdb.DuckDBPyConnection], duckdb.DuckDBPyRelation]

# RFC 2606 section 3 reserves these for documentation. They pass the public-suffix test, and
# example.com was a business clue on 638 services of the 2026-10-26 file.
RESERVED_DOMAINS = ["example.com", "example.net", "example.org"]
# A landlord names every rented machine after itself: one service per address, on many
# addresses, on networks it doesn't own. Both cut-offs are assumptions. On the 2026-10-26
# file, 5 addresses also caught mit.edu (9 addresses on Amazon); 10 and 20 differed by 43
# services with a finding.
SPREAD_MIN_ADDRESSES = 10
SPREAD_MAX_SERVICES_PER_ADDRESS = 1.5


def rules_ab_v1(con: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyRelation:
    """Drop landlord names (rule A), then the strongest remaining clue names the company (B).

    Owned network: class enterprise, edu or gov, and ASdb doesn't call it a landlord.
    Rule A: a domain with the landlord spread on networks it doesn't own stops counting
    everywhere, except as a scan hostname, the one clue a landlord can't set: someone pointed
    that name at the address. Reverse DNS and server self-names are set by whoever runs the
    machine, often the hoster (vps-6457677-x.dattaweb.com).
    Rule B, first match wins: scan hostname (High), the name a Windows or directory server
    reports (High), reverse DNS (Medium). Low when the remaining clues name two or more
    domains. With no clue left, a service on an owned network belongs to that network
    (Medium). Otherwise unknown.
    """
    return con.sql(
        f"""
        WITH svc AS (
          SELECT s.service_key, a.ip, a.asn, a.org,
            a.asn IS NOT NULL AND a.owner_class IN ('enterprise', 'edu', 'gov')
              AND NOT coalesce(l.landlord, false) AS owned
          FROM silver_service s
          JOIN silver_address a ON a.ip = s.ip
          LEFT JOIN asdb_landlord l ON l.asn = a.asn
          WHERE s.noise_reason IS NULL
        ),
        clue AS (
          SELECT DISTINCT e.service_key, e.normalized_value AS domain,
            CASE e.evidence_type WHEN 'scan_hostname' THEN 1 WHEN 'dns_hostname' THEN 3
              ELSE 2 END AS strength
          FROM silver_identity_evidence e
          SEMI JOIN svc ON svc.service_key = e.service_key
          WHERE e.is_infrastructure IS FALSE AND e.normalized_value IS NOT NULL
            AND NOT list_contains({RESERVED_DOMAINS}, e.normalized_value)
        ),
        spread AS (
          SELECT c.domain
          FROM clue c JOIN svc v ON v.service_key = c.service_key
          WHERE NOT v.owned
          GROUP BY c.domain
          HAVING count(DISTINCT v.ip) >= {SPREAD_MIN_ADDRESSES}
            AND count(DISTINCT c.service_key)
              <= {SPREAD_MAX_SERVICES_PER_ADDRESS} * count(DISTINCT v.ip)
        ),
        kept AS (
          SELECT c.* FROM clue c
          WHERE c.strength = 1 OR NOT EXISTS (SELECT 1 FROM spread WHERE spread.domain = c.domain)
        ),
        ranked AS (
          SELECT service_key, domain, strength,
            row_number() OVER (PARTITION BY service_key ORDER BY strength, domain) AS pick,
            count(DISTINCT domain) OVER (PARTITION BY service_key) AS domains
          FROM kept
        )
        SELECT v.service_key,
          coalesce(r.domain, CASE WHEN v.owned THEN v.asn END) AS company_key,
          CASE WHEN r.domain IS NOT NULL THEN 'domain' WHEN v.owned THEN 'network' END
            AS company_kind,
          CASE WHEN r.domain IS NOT NULL THEN r.domain WHEN v.owned THEN coalesce(v.org, v.asn) END
            AS company_name,
          CASE WHEN r.domain IS NULL THEN CASE WHEN v.owned THEN 'Medium' END
            WHEN r.domains > 1 THEN 'Low'
            WHEN r.strength < 3 THEN 'High'
            ELSE 'Medium' END AS confidence,
          CASE r.strength WHEN 1 THEN 'scan_hostname' WHEN 2 THEN 'server_name'
            WHEN 3 THEN 'reverse_dns' ELSE CASE WHEN v.owned THEN 'network' END END AS route,
          'rules_ab_v1' AS attributor
        FROM svc v
        LEFT JOIN ranked r ON r.service_key = v.service_key AND r.pick = 1
        """
    )


ATTRIBUTORS: dict[str, Attributor] = {"rules_ab_v1": rules_ab_v1}


def attribute(con: duckdb.DuckDBPyConnection, strategy: str) -> duckdb.DuckDBPyRelation:
    return ATTRIBUTORS[strategy](con)


def build(con: duckdb.DuckDBPyConnection, settings: Settings, staging: Path) -> None:
    (staging / "attribution").mkdir()
    stage.copy(
        con,
        attribute(con, settings.attributor).sql_query(),
        staging / "attribution" / "data.parquet",
    )
