"""Who a salesperson calls first: one score and one rank per company, per scoring rule.

Every rule runs on every build, so comparing two rules is a query on one table. A company
whose findings are all unscored keeps a row with no rank.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Literal

import duckdb

from pipeline import stage
from pipeline.settings import Settings

type CompanyScorer = Callable[[duckdb.DuckDBPyConnection, Path], duckdb.DuckDBPyRelation]

# How likely the named company is the right one. Drafted by AI, not validated.
CONFIDENCE_WEIGHT = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
# The same fault reported twice: as a scanner check and as its CVE, and as a Microsoft
# bulletin and its CVE. Counted once when ranking by breadth; both stay in `finding`.
SAME_FAULT = {"CVE-2014-0160": "heartbleed_vulnerable", "CVE-2015-1635": "MS15-034"}


def _ranked(
    con: duckdb.DuckDBPyConnection,
    staging: Path,
    aggregate: Literal["max", "sum"],
    name: str,
) -> duckdb.DuckDBPyRelation:
    """Per company: the aggregate of (finding score x that service's confidence weight).

    Weighting per service, before aggregating, stops a High-confidence minor service lending
    its weight to a Low-confidence critical one. The company's confidence is that of the
    service with the highest weighted score. Ties: confidence, then distinct finding types,
    then the share of the company's visible services with a finding, then the key, so every
    run gives the same order.
    """
    weights = ", ".join(f"('{level}', {w})" for level, w in CONFIDENCE_WEIGHT.items())
    same_fault = ", ".join(f"('{k}', '{v}')" for k, v in SAME_FAULT.items())
    return con.sql(
        f"""
        WITH a AS (
          SELECT * FROM {stage.read(staging, "attribution")} WHERE company_key IS NOT NULL
        ),
        w(confidence, weight) AS (VALUES {weights}),
        fault(finding_type, fault) AS (VALUES {same_fault}),
        f AS (
          SELECT a.company_key, a.company_kind, a.company_name, a.confidence, w.weight,
            a.attributor, f.service_key, f.score, f.finding_scorer, f.answers_model,
            coalesce(fault.fault, f.finding_type) AS fault,
            round(f.score * w.weight, 6) AS weighted
          FROM {stage.read(staging, "finding")} f
          JOIN a USING (service_key)
          JOIN w USING (confidence)
          LEFT JOIN fault USING (finding_type)
        ),
        visible AS (SELECT company_key, count(*) AS visible_services FROM a GROUP BY 1),
        per_company AS (
          SELECT company_key, any_value(company_kind) AS company_kind,
            any_value(company_name) AS company_name,
            {aggregate}(weighted) AS ranking_score,
            {aggregate}(score) AS company_score,
            arg_max(confidence, (coalesce(weighted, -1), weight)) AS confidence,
            count(DISTINCT fault) AS distinct_finding_types,
            count(DISTINCT service_key) AS services_with_finding,
            any_value(attributor) AS attributor,
            any_value(finding_scorer) AS finding_scorer,
            any_value(answers_model) AS answers_model
          FROM f GROUP BY company_key
        )
        SELECT '{name}' AS company_scorer, p.company_key, p.company_kind, p.company_name,
          CASE WHEN p.ranking_score IS NOT NULL THEN row_number() OVER (
            PARTITION BY p.ranking_score IS NULL
            ORDER BY p.ranking_score DESC,
              CASE p.confidence WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
              p.distinct_finding_types DESC,
              p.services_with_finding / v.visible_services DESC,
              p.company_key) END AS rank,
          p.ranking_score, p.company_score, p.confidence, p.distinct_finding_types,
          p.services_with_finding, v.visible_services,
          p.services_with_finding / v.visible_services AS finding_share,
          p.attributor, p.finding_scorer, p.answers_model
        FROM per_company p JOIN visible v USING (company_key)
        """
    )


def worst_x_confidence_v1(con: duckdb.DuckDBPyConnection, staging: Path) -> duckdb.DuckDBPyRelation:
    """The company's worst finding: the weakest-link view, which can't double-count."""
    return _ranked(con, staging, "max", "worst_x_confidence_v1")


def sum_x_confidence_v1(con: duckdb.DuckDBPyConnection, staging: Path) -> duckdb.DuckDBPyRelation:
    """The comparison rule. Large organisations rise for being large, and the same fault
    reported twice counts twice, both on purpose: it's what the worst-finding rule avoids."""
    return _ranked(con, staging, "sum", "sum_x_confidence_v1")


COMPANY_SCORERS: dict[str, CompanyScorer] = {
    "worst_x_confidence_v1": worst_x_confidence_v1,
    "sum_x_confidence_v1": sum_x_confidence_v1,
}


def build(con: duckdb.DuckDBPyConnection, _: Settings, staging: Path) -> None:
    every = " UNION ALL ".join(
        f"({scorer(con, staging).sql_query()})" for scorer in COMPANY_SCORERS.values()
    )
    (staging / "company").mkdir()
    stage.copy(con, every, staging / "company" / "data.parquet")
