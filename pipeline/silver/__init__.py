"""Silver: sightings folded into services, who owns each address, every clue, CVE and finding.

Only `service` is deduplicated. The other tables keep one row per sighting, so a finding
seen once is never lost to dedupe.
"""

import uuid
from datetime import UTC, date, datetime
from importlib.metadata import version
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.meta import (
    Check,
    Manifest,
    RunLog,
    Status,
    code_version,
    manifest_path,
    write_json,
)
from pipeline.ref import snapshot
from pipeline.settings import Settings
from pipeline.silver import address, checks, identity, service, sightings, signal, vuln

STEPS: list[tuple[str, stage.Step[Settings], tuple[str, ...]]] = [
    ("sightings", sightings.build, ("sightings",)),
    ("address", address.build, ("address",)),
    ("service", service.build, ("service",)),
    ("identity_candidates", identity.candidates, ("identity_candidates",)),
    ("identity_evidence", identity.evidence, ("identity_evidence",)),
    ("service_vuln", vuln.build, ("service_vuln",)),
    ("service_signal", signal.build, ("service_signal",)),
]
STEP_NAMES = [name for name, _, _ in STEPS]
UNPUBLISHED = ("sightings", "identity_candidates")


def build(manifest: Manifest, settings: Settings, start_at: str = STEP_NAMES[0]) -> RunLog:
    """Write the silver tables for one file already in bronze, check them, then publish."""
    log = RunLog(
        run_id=uuid.uuid4().hex,
        step="silver",
        file_id=manifest.file_id,
        started_at=datetime.now(UTC),
        resumed_from=None if start_at == STEP_NAMES[0] else start_at,
    )
    try:
        peeringdb_dir, as_of = snapshot.newest(settings.ref_root, "peeringdb")
    except snapshot.SnapshotError as e:
        _finish(log, manifest, settings.data_root, str(e))
        return log
    log.refs = {"peeringdb_as_of": as_of, "tldextract": version("tldextract")}

    bronze = settings.data_root / "bronze"
    setup = f"""
        CREATE VIEW bronze_banner AS SELECT * FROM read_parquet(
          '{bronze}/banner/file_id={manifest.file_id}/*.parquet', hive_partitioning=false);
        CREATE VIEW bronze_vuln AS SELECT * FROM read_parquet(
          '{bronze}/vuln/file_id={manifest.file_id}/*.parquet', hive_partitioning=false);
        CREATE VIEW peeringdb AS SELECT * FROM read_parquet('{peeringdb_dir}/*.parquet');
    """

    def run_checks(
        con: duckdb.DuckDBPyConnection, staging: Path, rows: dict[str, int]
    ) -> list[Check]:
        found, log.metrics = checks.run(con, staging, rows)
        age = datetime.now(UTC).date() - date.fromisoformat(as_of)
        log.metrics["peeringdb_age_days"] = float(age.days)
        return found

    error = stage.run(
        log, settings.data_root, "silver", STEPS, settings, start_at, run_checks, setup, UNPUBLISHED
    )
    _finish(log, manifest, settings.data_root, error)
    return log


def _finish(log: RunLog, manifest: Manifest, data_root: Path, error: str | None) -> None:
    """Record the outcome in the file's manifest and in this run's log.

    A silver failure leaves the file at bronze rather than failed: anything not at bronze
    is rebuilt by the bronze command, which would cost a full re-parse for a silver bug.
    """
    if error:
        manifest.status = Status.BRONZE
        manifest.error = f"silver: {error}"
    else:
        manifest.status = Status.SILVER
        manifest.error = None
        manifest.silver_run_id = log.run_id
        manifest.silver_code_version = code_version()
    log.finished_at = datetime.now(UTC)
    write_json(manifest_path(data_root, manifest.file_id), manifest)
    write_json(data_root / "_meta" / "run" / f"{log.run_id}.json", log)
