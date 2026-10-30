from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    """Step 3: one row per service, the only deduplicated table.

    The row shown is the latest sighting that identified a product, else the latest. Ties on
    time go to the higher rec_id, so a re-run or a reordered input shows the same row.
    """
    (staging / "service").mkdir()
    stage.copy(
        con,
        f"""
        WITH s AS (
          SELECT service_key,
            any_value(ip) AS ip, any_value(ip_version) AS ip_version, any_value(port) AS port,
            any_value(transport) AS transport, any_value(hostname) AS hostname,
            count(*)::INTEGER AS sightings, min(seen_at) AS first_seen, max(seen_at) AS last_seen,
            -- A struct, never NULL itself, so fields that are NULL still come from the same row
            arg_max({{'rec_id': rec_id, 'product': product, 'version': version, 'waf': http_waf}},
                    (product IS NOT NULL, seen_at, rec_id)) AS shown
          FROM {stage.read(staging, "sightings")}
          GROUP BY service_key
        )
        SELECT s.service_key, s.ip, s.ip_version, s.port, s.transport, s.hostname, s.sightings,
          s.first_seen, s.last_seen, shown.rec_id AS shown_rec_id, shown.product AS product,
          shown.version AS version, shown.waf AS http_waf,
          CASE WHEN a.is_honeypot THEN 'honeypot'
            WHEN a.answers_everything THEN 'answers_everything'
            WHEN a.owner_class = 'cdn' AND s.hostname IS NULL THEN 'cdn_edge'
          END AS noise_reason
        FROM s JOIN {stage.read(staging, "address")} a USING (ip)
        """,
        staging / "service" / "data.parquet",
    )
