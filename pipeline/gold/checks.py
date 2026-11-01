from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.gold.attribution import RESERVED_DOMAINS
from pipeline.meta import Check


def run(con: duckdb.DuckDBPyConnection, staging: Path) -> tuple[list[Check], dict[str, float]]:
    """Blocking checks on the staged gold tables, and the run-log metrics that don't block."""
    attribution = stage.read(staging, "attribution")
    finding = stage.read(staging, "finding")
    company = stage.read(staging, "company")

    def one(sql: str) -> tuple[int, ...]:
        row = con.execute(sql).fetchone()
        assert row is not None
        return tuple(int(x or 0) for x in row)

    (services,) = one("SELECT count(*) FROM silver_service WHERE noise_reason IS NULL")
    rows, keys, half_unknown, reserved, unlabelled = one(
        f"SELECT count(*), count(DISTINCT service_key), "
        "count(*) FILTER (WHERE (company_key IS NULL) <> (confidence IS NULL)), "
        f"count(*) FILTER (WHERE list_contains({RESERVED_DOMAINS}, company_key)), "
        f"count(*) FILTER (WHERE attributor IS NULL) FROM {attribution}"
    )
    checks = [
        Check(
            name="attribution_one_row_per_service",
            blocking=True,
            passed=rows == keys == services,
            detail=f"{rows:,} rows, {keys:,} keys, {services:,} non-noise services",
        ),
        Check(
            name="attribution_unknown_is_whole",
            blocking=True,
            passed=half_unknown == 0,
            detail=f"{half_unknown:,} rows with a company but no confidence, or the reverse",
        ),
        Check(
            name="attribution_no_reserved_domain",
            blocking=True,
            passed=reserved == 0,
            detail=f"{reserved:,} rows",
        ),
        Check(
            name="attribution_labelled",
            blocking=True,
            passed=unlabelled == 0,
            detail=f"{unlabelled:,} rows without an attributor",
        ),
    ]

    on_noise, unverified = one(
        f"SELECT count(*) FILTER (WHERE s.noise_reason IS NOT NULL OR a.owner_class = 'cdn'), "
        "count(*) FILTER (WHERE f.kind = 'vulnerability' AND NOT EXISTS (SELECT 1 FROM "
        "silver_service_vuln v WHERE v.service_key = f.service_key AND v.cve = f.finding_type "
        f"AND v.verified)) FROM {finding} f JOIN silver_service s USING (service_key) "
        "JOIN silver_address a ON a.ip = s.ip"
    )
    duplicate_rank, unscored_rank = one(
        "SELECT count(rank) - count(DISTINCT (company_scorer, rank)) "
        "FILTER (WHERE rank IS NOT NULL), "
        f"count(*) FILTER (WHERE rank IS NOT NULL AND ranking_score IS NULL) FROM {company}"
    )
    (answered,) = one("SELECT count(*) FILTER (WHERE status = 'answered') FROM finding_answers")
    checks += [
        Check(
            name="finding_not_on_noise_or_cdn",
            blocking=True,
            passed=on_noise == 0,
            detail=f"{on_noise:,} findings on noise or CDN services",
        ),
        Check(
            name="finding_vulnerability_verified",
            blocking=True,
            passed=unverified == 0,
            detail=f"{unverified:,} vulnerability findings without a verified sighting",
        ),
        Check(
            name="company_rank_unique",
            blocking=True,
            passed=duplicate_rank == 0,
            detail=f"{duplicate_rank:,} repeated ranks within a scorer",
        ),
        Check(
            name="company_ranked_only_when_scored",
            blocking=True,
            passed=unscored_rank == 0,
            detail=f"{unscored_rank:,} ranked companies without a ranking score",
        ),
        Check(
            name="finding_answers_present",
            blocking=False,
            passed=answered > 0,
            detail=f"{answered:,} answered finding types for the configured model; "
            "with none, every finding is unscored and no company is ranked",
        ),
    ]

    metrics: dict[str, float] = {}
    scored, unscored, unscored_types, unattributed = one(
        f"SELECT count(*) FILTER (WHERE score IS NOT NULL), count(*) FILTER (WHERE score IS NULL), "
        "count(DISTINCT finding_type) FILTER (WHERE score IS NULL), "
        f"count(*) FILTER (WHERE service_key IN (SELECT service_key FROM {attribution} "
        f"WHERE company_key IS NULL)) FROM {finding}"
    )
    metrics["finding.scored"] = scored
    metrics["finding.unscored"] = unscored
    metrics["finding.unscored_types"] = unscored_types
    metrics["finding.on_unattributed_services"] = unattributed
    for scorer, ranked, unranked in con.execute(
        f"SELECT company_scorer, count(rank), count(*) - count(rank) FROM {company} GROUP BY 1"
    ).fetchall():
        metrics[f"company.{scorer}.ranked"] = ranked
        metrics[f"company.{scorer}.unranked"] = unranked
    with_signal = "service_key IN (SELECT service_key FROM silver_service_signal)"
    for scope, where in (("all", "true"), ("with_signal", with_signal)):
        attributed, unknown = one(
            f"SELECT count(*) FILTER (WHERE company_key IS NOT NULL), "
            f"count(*) FILTER (WHERE company_key IS NULL) FROM {attribution} WHERE {where}"
        )
        metrics[f"attribution.{scope}.attributed"] = attributed
        metrics[f"attribution.{scope}.unknown"] = unknown
        for column in ("confidence", "route"):
            for value, n in con.execute(
                f"SELECT {column}, count(*) FROM {attribution} "
                f"WHERE {where} AND {column} IS NOT NULL GROUP BY 1"
            ).fetchall():
                metrics[f"attribution.{scope}.{column}.{value}"] = n
    (metrics["attribution.companies"],) = one(
        f"SELECT count(DISTINCT company_key) FROM {attribution}"
    )
    ruled_out, missing = one(
        "SELECT count(*) FILTER (WHERE a.owner_class IN ('enterprise', 'edu', 'gov') "
        "AND l.landlord), count(DISTINCT a.asn) FILTER (WHERE l.asn IS NULL) "
        "FROM silver_service s JOIN silver_address a ON a.ip = s.ip "
        "LEFT JOIN asdb_landlord l ON l.asn = a.asn WHERE s.noise_reason IS NULL"
    )
    metrics["asdb.services_ruled_out_as_landlord"] = ruled_out
    metrics["asdb.networks_not_listed"] = missing
    return checks, metrics
