"""Silver: sightings folded into services, who owns each address, and every clue and CVE.

Only `service` is deduplicated. The other tables keep one row per sighting, so a finding
seen once is never lost to dedupe.
"""

import subprocess
import uuid
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import duckdb

from pipeline import stage
from pipeline.meta import Check, Manifest, RunLog, Status, manifest_path, write_json
from pipeline.ref import peeringdb
from pipeline.settings import Settings
from pipeline.silver import address, checks, identity, service, sightings, vuln

STEPS: list[tuple[str, stage.Step[Settings], tuple[str, ...]]] = [
    ("sightings", sightings.build, ("sightings",)),
    ("address", address.build, ("address",)),
    ("service", service.build, ("service",)),
    ("identity_candidates", identity.candidates, ("identity_candidates",)),
    ("identity_evidence", identity.evidence, ("identity_evidence",)),
    ("service_vuln", vuln.build, ("service_vuln",)),
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
        snapshot, as_of = peeringdb.newest(settings.ref_root)
    except peeringdb.SnapshotError as e:
        _finish(log, manifest, settings.data_root, str(e))
        return log
    log.refs = {"peeringdb_as_of": as_of.isoformat(), "tldextract": version("tldextract")}

    bronze = settings.data_root / "bronze"
    setup = f"""
        CREATE VIEW bronze_banner AS SELECT * FROM read_parquet(
          '{bronze}/banner/file_id={manifest.file_id}/*.parquet', hive_partitioning=false);
        CREATE VIEW bronze_vuln AS SELECT * FROM read_parquet(
          '{bronze}/vuln/file_id={manifest.file_id}/*.parquet', hive_partitioning=false);
        CREATE VIEW peeringdb AS SELECT * FROM read_parquet('{snapshot}/*.parquet');
    """

    def run_checks(
        con: duckdb.DuckDBPyConnection, staging: Path, rows: dict[str, int]
    ) -> list[Check]:
        found, log.metrics = checks.run(con, staging, rows)
        log.metrics["peeringdb_age_days"] = float((datetime.now(UTC).date() - as_of).days)
        return found

    error = stage.run(
        log, settings.data_root, "silver", STEPS, settings, start_at, run_checks, setup, UNPUBLISHED
    )
    _finish(log, manifest, settings.data_root, error)
    return log


def _code_version() -> str:
    """The git commit of this code, with "-dirty" when the tree has uncommitted changes."""
    here = Path(__file__).parent
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=here
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
            cwd=here,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{commit}-dirty" if dirty else commit


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
        manifest.silver_code_version = _code_version()
    log.finished_at = datetime.now(UTC)
    write_json(manifest_path(data_root, manifest.file_id), manifest)
    write_json(data_root / "_meta" / "run" / f"{log.run_id}.json", log)
