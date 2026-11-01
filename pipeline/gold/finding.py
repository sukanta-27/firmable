"""How bad each finding is: the model's answers per finding type, turned into a score.

A strategy reads the views `finding_answers` (this run's model and prompt version) and
`kev_catalog`, and returns one row per finding type. A type with no answered row is unscored:
kept, counted, never guessed.
"""

from collections.abc import Callable
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.ref.finding_scores import Answer
from pipeline.settings import Settings

type FindingScorer = Callable[[duckdb.DuckDBPyConnection], duckdb.DuckDBPyRelation]


def setup_sql(settings: Settings) -> str:
    """Views over the answers file and CISA's KEV catalog. With no answers file yet, the
    view is empty, so gold still runs and every finding is unscored."""
    fields = list(Answer.model_fields)
    if settings.answers_path.exists():
        columns = "{" + ", ".join(f"{f}: 'VARCHAR'" for f in fields) + "}"
        answers = (
            f"SELECT * FROM read_json('{settings.answers_path}', format = 'newline_delimited', "
            f"columns = {columns}) WHERE model = '{settings.answers_model}' "
            f"AND prompt_version = '{settings.prompt_version}'"
        )
    else:
        nulls = ", ".join(f"NULL::VARCHAR AS {f}" for f in fields)
        answers = f"SELECT {nulls} WHERE false"
    return f"""
        CREATE VIEW finding_answers AS {answers};
        CREATE VIEW kev_catalog AS
        SELECT v.cveID AS cve FROM (SELECT unnest(vulnerabilities) AS v
          FROM read_json('{settings.kev_path}', maximum_object_size = 104857600));
    """


def ssvc_v1(con: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyRelation:
    """Severity from technical impact x likelihood from exploitation and automatability.

    Questions adapted from CISA's SSVC. Both mappings were drafted by AI and accepted by
    the owner as an unvalidated assumption. A KEV listing overrides the model's
    exploitation answer, which is kept beside it as `exploitation_blind`.
    """
    return con.sql(
        """
        WITH a AS (
          SELECT a.item_id, a.exploitation AS exploitation_blind,
            CASE WHEN k.cve IS NOT NULL THEN 'active' ELSE a.exploitation END
              AS exploitation_final,
            a.automatable,
            CASE a.technical_impact WHEN 'total' THEN 3 WHEN 'partial' THEN 2
              WHEN 'information' THEN 1 END AS severity
          FROM finding_answers a
          LEFT JOIN (SELECT DISTINCT cve FROM kev_catalog) k ON k.cve = a.item_id
          WHERE a.status = 'answered'
        )
        SELECT item_id, exploitation_blind, exploitation_final, severity,
          CASE exploitation_final
            WHEN 'active' THEN CASE automatable WHEN 'yes' THEN 4 ELSE 3 END
            WHEN 'poc' THEN CASE automatable WHEN 'yes' THEN 3 ELSE 2 END
            WHEN 'none' THEN 1 END AS likelihood,
          severity * likelihood AS score
        FROM a
        """
    )


FINDING_SCORERS: dict[str, FindingScorer] = {"ssvc_v1": ssvc_v1}


def build(con: duckdb.DuckDBPyConnection, settings: Settings, staging: Path) -> None:
    """One row per service x finding type, on services that are not noise or CDN.

    `silver.service_vuln` keeps every sighting's CVEs, CDN and noise included, unlike
    `service_signal`, so the eligibility filter is applied here to both.
    """
    scores = FINDING_SCORERS[settings.finding_scorer](con).sql_query()
    (staging / "finding").mkdir()
    stage.copy(
        con,
        f"""
        WITH eligible AS (
          SELECT s.service_key FROM silver_service s JOIN silver_address a ON a.ip = s.ip
          WHERE s.noise_reason IS NULL AND a.owner_class IS DISTINCT FROM 'cdn'
        ),
        sighted AS (
          SELECT service_key, signal_code AS finding_type, 'exposure' AS kind, evidence_text,
            seen_at, rec_id
          FROM silver_service_signal
          UNION ALL
          SELECT service_key, cve, 'vulnerability', NULL, seen_at, rec_id
          FROM silver_service_vuln WHERE verified
        ),
        one AS (
          SELECT service_key, finding_type, kind,
            arg_min(evidence_text, (seen_at, rec_id)) AS evidence_text
          FROM sighted SEMI JOIN eligible USING (service_key)
          GROUP BY ALL
        )
        SELECT one.service_key, one.finding_type, one.kind, one.evidence_text,
          sc.exploitation_blind, sc.exploitation_final, sc.severity, sc.likelihood, sc.score,
          '{settings.finding_scorer}' AS finding_scorer,
          '{settings.answers_model}' AS answers_model,
          '{settings.prompt_version}' AS prompt_version
        FROM one LEFT JOIN ({scores}) sc ON sc.item_id = one.finding_type
        """,
        staging / "finding" / "data.parquet",
    )
