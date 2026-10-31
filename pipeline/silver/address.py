from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings
from pipeline.silver.owner_class import peeringdb_class_sql


def build(con: duckdb.DuckDBPyConnection, settings: Settings, staging: Path) -> None:
    """Step 2: one row per IP, with its network and who owns it.

    A tag on any sighting tags the address. On the 2026-10-26 file, sightings of one address
    disagreed on the cdn tag at 185 of 4,992,440 addresses, cloud at 971, honeypot at 5,094;
    and never on asn, org or country, so those come from the latest sighting.
    """
    (staging / "address").mkdir()
    stage.copy(
        con,
        f"""
        WITH per_ip AS (
          SELECT ip,
            arg_max({{'v': ip_version, 'asn': asn, 'org': org, 'isp': isp, 'cc': country_code}},
                    (seen_at, rec_id)) AS latest,
            bool_or(list_contains(tags, 'cdn')) AS cdn,
            bool_or(list_contains(tags, 'cloud')) AS cloud,
            bool_or(list_contains(tags, 'honeypot')) AS is_honeypot,
            count(DISTINCT (port, transport))::INTEGER AS ports
          FROM {stage.read(staging, "sightings")}
          GROUP BY ip
        ),
        cloud_asn AS (
          SELECT latest.asn AS asn
          FROM per_ip
          WHERE latest.asn IS NOT NULL
          GROUP BY latest.asn
          HAVING count(*) >= {settings.asn_cloud_min_addresses}
            AND count(*) FILTER (WHERE cloud AND NOT cdn) / count(*)
              >= {settings.asn_cloud_min_share}
        ),
        net AS (
          SELECT asn, {peeringdb_class_sql("info_types")} AS cls,
            nullif(array_to_string(info_types, '|'), '') AS types
          FROM peeringdb
        )
        SELECT ip, latest.v AS ip_version, latest.asn AS asn, latest.org AS org,
          latest.isp AS isp, latest.cc AS country_code,
          CASE WHEN cdn THEN 'cdn' WHEN cloud OR cloud_asn.asn IS NOT NULL THEN 'cloud'
            ELSE coalesce(net.cls, 'unknown') END AS owner_class,
          CASE WHEN cdn OR cloud THEN 'scanner_tag'
            WHEN cloud_asn.asn IS NOT NULL THEN 'asn_cloud_share'
            WHEN net.cls <> 'unknown' THEN 'peeringdb' ELSE 'none' END AS owner_class_source,
          CASE WHEN cdn THEN 'cdn' WHEN cloud THEN 'cloud'
            WHEN cloud_asn.asn IS NOT NULL THEN 'asn_cloud_share' ELSE net.types END
            AS owner_class_detail,
          is_honeypot, ports,
          ports > {settings.answers_everything_ports} AS answers_everything
        FROM per_ip
        LEFT JOIN cloud_asn ON cloud_asn.asn = latest.asn
        LEFT JOIN net ON net.asn = latest.asn
        """,
        staging / "address" / "data.parquet",
    )
