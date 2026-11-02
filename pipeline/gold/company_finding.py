"""Every finding on a service that names a company, with what a salesperson needs to read it.

The app reads this instead of joining gold to silver and bronze per request: findings on
services with no company are never shown, and leaving them out keeps the table small enough to
ship inside the app's image.
"""

from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.settings import Settings


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    (staging / "company_finding").mkdir()
    stage.copy(
        con,
        f"""
        SELECT a.company_key, a.company_kind, a.company_name,
          f.service_key, s.ip, s.port, s.transport, s.product, s.version, s.hostname,
          s.first_seen, s.last_seen, ad.country_code,
          a.route, a.confidence,
          f.finding_type, f.kind, f.evidence_text, f.exploitation_blind, f.exploitation_final,
          f.severity, f.likelihood, f.score,
          ans.status AS answer_status, ans.automatable, ans.technical_impact,
          ans.salesperson_line,
          t.summary AS cve_summary,
          a.attributor, f.finding_scorer, f.answers_model, f.prompt_version
        FROM {stage.read(staging, "finding")} f
        JOIN {stage.read(staging, "attribution")} a USING (service_key)
        JOIN silver_service s USING (service_key)
        JOIN silver_address ad ON ad.ip = s.ip
        LEFT JOIN finding_answers ans ON ans.item_id = f.finding_type
        LEFT JOIN bronze_cve_text t ON f.kind = 'vulnerability' AND t.cve = f.finding_type
        WHERE a.company_key IS NOT NULL
        """,
        staging / "company_finding" / "data.parquet",
    )
