"""Gold: whose each service is, how bad each finding is, and who a salesperson calls first.

Every table names the strategies that made it, so outputs of different strategies never mix
unlabelled. Gold reads one file's silver partitions and its bronze CVE descriptions, and
never calls a model.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.gold import attribution, checks, company, company_finding, finding
from pipeline.meta import (
    Check,
    Manifest,
    RunLog,
    Status,
    code_version,
    manifest_path,
    write_json,
)
from pipeline.ref import asdb, snapshot
from pipeline.settings import Settings

STEPS: list[tuple[str, stage.Step[Settings], tuple[str, ...]]] = [
    ("attribution", attribution.build, ("attribution",)),
    ("finding", finding.build, ("finding",)),
    ("company", company.build, ("company",)),
    ("company_finding", company_finding.build, ("company_finding",)),
]
STEP_NAMES = [name for name, _, _ in STEPS]
SILVER_TABLES = ["service", "address", "identity_evidence", "service_signal", "service_vuln"]


def build(manifest: Manifest, settings: Settings, start_at: str = STEP_NAMES[0]) -> RunLog:
    """Write the gold tables for one file already in silver, check them, then publish."""
    log = RunLog(
        run_id=uuid.uuid4().hex,
        step="gold",
        file_id=manifest.file_id,
        started_at=datetime.now(UTC),
        resumed_from=None if start_at == STEP_NAMES[0] else start_at,
    )
    try:
        asdb_dir, asdb_as_of = snapshot.newest(settings.ref_root, "asdb")
    except snapshot.SnapshotError as e:
        _finish(log, manifest, settings.data_root, str(e))
        return log
    kev_version = json.loads(settings.kev_path.read_text()).get("catalogVersion", "unknown")
    log.refs = {
        "asdb_as_of": asdb_as_of,
        "kev_catalog_version": kev_version,
        "attributor": settings.attributor,
        "finding_scorer": settings.finding_scorer,
        "answers_model": settings.answers_model,
        "prompt_version": settings.prompt_version,
        "company_scorers": ",".join(company.COMPANY_SCORERS),
    }

    silver = settings.data_root / "silver"
    views = "".join(
        f"CREATE VIEW silver_{t} AS SELECT * FROM read_parquet("
        f"'{silver}/{t}/file_id={manifest.file_id}/*.parquet', hive_partitioning=false);\n"
        for t in SILVER_TABLES
    )
    cve_text = settings.data_root / "bronze" / "cve_text" / f"file_id={manifest.file_id}"
    views += (
        "CREATE VIEW bronze_cve_text AS SELECT * FROM read_parquet("
        f"'{cve_text}/*.parquet', hive_partitioning=false);\n"
    )
    setup = views + asdb.view_sql(asdb_dir) + finding.setup_sql(settings)

    def run_checks(
        con: duckdb.DuckDBPyConnection, staging: Path, rows: dict[str, int]
    ) -> list[Check]:
        found, log.metrics = checks.run(con, staging)
        return found

    error = stage.run(log, settings.data_root, "gold", STEPS, settings, start_at, run_checks, setup)
    _finish(log, manifest, settings.data_root, error)
    return log


def _finish(log: RunLog, manifest: Manifest, data_root: Path, error: str | None) -> None:
    """Record the outcome in the file's manifest and in this run's log.

    A gold failure leaves the file at silver, so fixing gold never forces a silver rebuild.
    """
    if error:
        manifest.status = Status.SILVER
        manifest.error = f"gold: {error}"
    else:
        manifest.status = Status.GOLD
        manifest.error = None
        manifest.gold_run_id = log.run_id
        manifest.gold_code_version = code_version()
    log.finished_at = datetime.now(UTC)
    write_json(manifest_path(data_root, manifest.file_id), manifest)
    write_json(data_root / "_meta" / "run" / f"{log.run_id}.json", log)
