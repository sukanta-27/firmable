import os
import subprocess
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from api.reports import ReportStamp


class Status(StrEnum):
    RECEIVED = "received"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    FAILED = "failed"


class Manifest(BaseModel):
    file_id: str
    source_uri: str
    size_bytes: int
    compression: str
    received_at: datetime
    lines: int
    landing_seconds: float
    status: Status = Status.RECEIVED
    records: int | None = None
    unreadable: int | None = None
    unknown_keys: dict[str, int] = {}
    error: str | None = None
    silver_run_id: str | None = None
    # git commit of the code that built silver, with "-dirty" when the tree had changes.
    silver_code_version: str | None = None
    gold_run_id: str | None = None
    gold_code_version: str | None = None


class Check(BaseModel):
    name: str
    blocking: bool
    passed: bool
    detail: str


class RunLog(BaseModel):
    run_id: str
    step: str
    file_id: str
    started_at: datetime
    finished_at: datetime | None = None
    resumed_from: str | None = None
    seconds: dict[str, float] = {}
    peaks: dict[str, dict[str, float]] = {}
    rows: dict[str, int] = {}
    checks: list[Check] = []
    refs: dict[str, str] = {}
    metrics: dict[str, float] = {}


def manifest_path(data_root: Path, file_id: str) -> Path:
    return data_root / "_meta" / "manifest" / f"{file_id}.json"


def find_manifest(data_root: Path, source: Path) -> Manifest | None:
    """The manifest landing wrote for this source file, matched by path and size."""
    uri, size = str(source.resolve()), source.stat().st_size
    for path in (data_root / "_meta" / "manifest").glob("*.json"):
        m = Manifest.model_validate_json(path.read_text())
        if m.source_uri == uri and m.size_bytes == size:
            return m
    return None


def read_manifest(data_root: Path, file_id: str) -> Manifest | None:
    path = manifest_path(data_root, file_id)
    return Manifest.model_validate_json(path.read_text()) if path.exists() else None


def write_json(path: Path, model: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(model.model_dump_json(indent=2))
    os.replace(tmp, path)


def code_version() -> str:
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


def report_stamp(command: str, **inputs: str) -> ReportStamp:
    return ReportStamp(
        command=command, ran_at=datetime.now(UTC), code_version=code_version(), inputs=inputs
    )
