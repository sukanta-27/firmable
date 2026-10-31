"""Step 7: every security finding in every sighting, one row per sighting x finding.

Services with a `noise_reason` and services on `cdn` addresses get no rows. A CDN record
describes the CDN, not the customer, and a honeypot's findings are bait; skipping them here
means gold can't forget to.
"""

from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings
from pipeline.silver.signal_rules import RULES


def _matches() -> str:
    """A list with one {code, field, text} entry per rule the row matches."""
    entries = ",\n".join(
        f"CASE WHEN {r.predicate} THEN {{'code': '{code}', 'field': {r.evidence_field}, "
        f"'text': {r.evidence}}} END"
        for code, r in RULES.items()
    )
    return f"list_filter([\n{entries}\n], lambda m: m IS NOT NULL)"


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    (staging / "service_signal").mkdir()
    stage.copy(
        con,
        f"""
        WITH eligible AS (
          SELECT s.rec_id, s.service_key, s.seen_at, a.ports AS ip_ports,
            sv.sightings AS service_sightings
          FROM {stage.read(staging, "sightings")} s
          JOIN {stage.read(staging, "service")} sv USING (service_key)
          JOIN {stage.read(staging, "address")} a ON a.ip = s.ip
          WHERE sv.noise_reason IS NULL AND a.owner_class IS DISTINCT FROM 'cdn'
        ),
        mac AS (
          SELECT json_extract_string(lantronix, '$.mac') AS mac, count(DISTINCT ip) AS mac_ips
          FROM bronze_banner
          WHERE parse_error IS NULL AND json_extract(lantronix, '$.password') IS NOT NULL
          GROUP BY 1
        ),
        module_list AS (
          SELECT CAST(json_extract(rsync, '$.modules') AS VARCHAR) AS modules,
            count(DISTINCT ip) AS module_list_ips
          FROM bronze_banner
          WHERE parse_error IS NULL AND json_extract_string(rsync, '$.authentication') = 'false'
          GROUP BY 1
        ),
        matched AS (
          SELECT e.service_key, e.rec_id, e.seen_at, {_matches()} AS found
          FROM bronze_banner b
          JOIN eligible e USING (rec_id)
          LEFT JOIN mac ON mac.mac = json_extract_string(b.lantronix, '$.mac')
          LEFT JOIN module_list ON module_list.modules
            = CAST(json_extract(b.rsync, '$.modules') AS VARCHAR)
          WHERE b.parse_error IS NULL
        )
        SELECT service_key, rec_id, seen_at, m.code AS signal_code, m.field AS evidence_field,
          left(m.text, 300) AS evidence_text
        FROM (SELECT service_key, rec_id, seen_at, unnest(found) AS m FROM matched)
        """,
        staging / "service_signal" / "data.parquet",
    )
