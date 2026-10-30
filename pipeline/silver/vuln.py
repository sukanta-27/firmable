from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    """Step 6: every CVE listed on every sighting, with the service it belongs to."""
    (staging / "service_vuln").mkdir()
    stage.copy(
        con,
        f"""
        SELECT s.service_key, v.rec_id, s.seen_at, v.cve, v.verified, v.cvss, v.cvss_version,
          v.epss, v.ranking_epss, v.kev, v.ransomware_campaign
        FROM bronze_vuln v JOIN {stage.read(staging, "sightings")} s USING (rec_id)
        """,
        staging / "service_vuln" / "data.parquet",
    )
