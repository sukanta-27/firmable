"""Steps 4 and 5: clues to which business a service belongs to, one row per sighting x clue.

Two routes, named for where the name came from:
- scan_hostname: the website name the scanner asked for.
- dns_hostname: an entry of Shodan's `hostnames[]`. Not only reverse DNS: when a sighting
  has a scan hostname, `hostnames[]` contained it on 737,413 of 737,690 such records
  (2026-10-26 file). Those echoes are dropped here, so one clue never counts as two routes
  agreeing.

A name under a platform suffix from the Public Suffix List's private section (cloudfront.net,
cloudapp.net, cdn.cloudflare.net) names the platform, not a business, so it is infrastructure.
Keeping the label before the suffix as the customer was measured and rejected: on the 2M-line
slice those labels were machine ids (d3o7okqs1lmm3v.cloudfront.net) or, for Cloudflare, the
wrong part of the customer's own name (edu.cdn.cloudflare.net). The exception is a real domain
embedded before the suffix (www.btig.com.cdn.cloudflare.net -> btig.com): 3,257 slice rows on
524 domains, about 120 of them false (apim-x.unique.management.azure-api.net -> unique.management).
"""

import json
from pathlib import Path

import duckdb
import tldextract

from pipeline import stage
from pipeline.settings import Settings

# The suffix list bundled with the installed tldextract, so a run never fetches and its
# version is pinned by uv.lock. cache_dir=None keeps it from writing a cache anywhere.
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
_extract_private = tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True
)

IP_NUMBER_PATTERN = r"\d{1,3}[-.]\d{1,3}[-.]\d{1,3}"


def registrable_domain(name: str) -> tuple[str | None, str | None]:
    """The domain a name belongs to, and whether it sits under a platform.

    `mail.acme.co.uk` -> (`acme.co.uk`, None); `d1x.cloudfront.net` -> (`cloudfront.net`,
    `platform`); `www.btig.com.cdn.cloudflare.net` -> (`btig.com`, `customer_inside`).
    The domain is None for IP literals, bare suffixes and `localhost`.
    """
    domain = _extract(name).top_domain_under_public_suffix or None
    under = _extract_private(name)
    if not under.is_private:
        return domain, None
    before = name.removesuffix("." + under.suffix)
    inside = _extract(before).top_domain_under_public_suffix if before != name else ""
    if inside:
        return inside, "customer_inside"
    return domain, "platform"


def candidates(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    """Every clue with its registrable domain, before any is dropped or judged."""
    sightings = stage.read(staging, "sightings")
    # Looked up once per distinct name, in Python: a DuckDB Python function would need numpy.
    names = staging / "_names.jsonl"
    distinct = con.execute(
        f"""
        SELECT hostname FROM {sightings} WHERE hostname IS NOT NULL
        UNION
        SELECT unnest(hostnames) FROM {sightings}
        """
    )
    with names.open("w") as out:
        while batch := distinct.fetchmany(100_000):
            for (n,) in batch:
                if n is None:
                    continue
                domain, platform = registrable_domain(n.lower())
                record = {"raw_value": n, "normalized_value": domain, "platform": platform}
                out.write(json.dumps(record) + "\n")
    (staging / "identity_candidates").mkdir()
    stage.copy(
        con,
        f"""
        WITH clue AS (
          SELECT service_key, rec_id, seen_at, ip, 'scan_hostname' AS evidence_type,
            hostname AS raw_value
          FROM {sightings}
          WHERE hostname IS NOT NULL
          UNION ALL
          SELECT service_key, rec_id, seen_at, ip, 'dns_hostname', raw_value
          FROM (
            SELECT service_key, rec_id, seen_at, ip, hostname, unnest(hostnames) AS raw_value
            FROM {sightings}
          )
          WHERE raw_value IS DISTINCT FROM hostname
        ),
        names AS (
          SELECT * FROM read_json('{names}',
            columns = {{raw_value: 'VARCHAR', normalized_value: 'VARCHAR', platform: 'VARCHAR'}})
        )
        SELECT clue.*, names.normalized_value, names.platform
        FROM clue JOIN names USING (raw_value)
        """,
        staging / "identity_candidates" / "data.parquet",
    )
    names.unlink()


def evidence(con: duckdb.DuckDBPyConnection, settings: Settings, staging: Path) -> None:
    """Clues that name a registrable domain, each marked if the domain names a landlord.

    ip_number_name: a domain on enough addresses whose names are mostly IP numbers
    (179-125-1-1.provider.net). network_main_domain: a domain making up a large share of the
    names on one ISP, hosting or CDN network. Thresholds come from the archived analysis, which
    grouped networks by org rather than ASN, and were not re-tested. platform_domain: a name
    under a platform suffix with no real domain embedded before it.
    """
    cands = stage.read(staging, "identity_candidates")
    (staging / "identity_evidence").mkdir()
    stage.copy(
        con,
        f"""
        WITH ev AS (SELECT * FROM {cands} WHERE normalized_value IS NOT NULL),
        ip_number AS (
          SELECT normalized_value
          FROM ev
          GROUP BY normalized_value
          HAVING count(DISTINCT ip) >= {settings.ip_number_min_addresses}
            AND count(DISTINCT raw_value) FILTER (
                  WHERE regexp_matches(raw_value, '{IP_NUMBER_PATTERN}'))
                >= {settings.ip_number_min_share} * count(DISTINCT raw_value)
        ),
        landlord_ev AS (
          SELECT a.asn, ev.rec_id, ev.normalized_value
          FROM ev JOIN {stage.read(staging, "address")} a USING (ip)
          WHERE a.owner_class IN ('isp', 'hosting', 'cdn') AND a.asn IS NOT NULL
        ),
        per_asn AS (
          SELECT asn, count(DISTINCT rec_id) AS records FROM landlord_ev GROUP BY asn
        ),
        network_main AS (
          SELECT DISTINCT normalized_value
          FROM (
            SELECT asn, normalized_value, count(DISTINCT rec_id) AS records
            FROM landlord_ev GROUP BY asn, normalized_value
          ) d JOIN per_asn USING (asn)
          WHERE d.records >= {settings.network_domain_min_records}
            AND d.records >= {settings.network_domain_min_share} * per_asn.records
        )
        SELECT ev.service_key, ev.rec_id, ev.seen_at, ev.evidence_type, ev.raw_value,
          ev.normalized_value,
          i.normalized_value IS NOT NULL OR m.normalized_value IS NOT NULL
            OR ev.platform IS NOT DISTINCT FROM 'platform' AS is_infrastructure,
          CASE WHEN i.normalized_value IS NOT NULL THEN 'ip_number_name'
            WHEN m.normalized_value IS NOT NULL THEN 'network_main_domain'
            WHEN ev.platform = 'platform' THEN 'platform_domain'
          END AS infra_reason
        FROM ev
        LEFT JOIN ip_number i ON i.normalized_value = ev.normalized_value
        LEFT JOIN network_main m ON m.normalized_value = ev.normalized_value
        """,
        staging / "identity_evidence" / "data.parquet",
    )
