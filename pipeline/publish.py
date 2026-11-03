"""Choose which scan the app shows: copy one file's app tables and provenance to one folder.

The app reads nothing else, and the deploy ships only this folder, so the image's code and
data always travel together.
"""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import duckdb
from pydantic import BaseModel

from pipeline.eval import ranking_report_path
from pipeline.meta import Manifest, Status, code_version, write_json
from pipeline.settings import Settings

TABLES = ("company", "company_finding")


class Published(BaseModel):
    file_id: str
    data_root: str
    published_at: datetime
    code_version: str
    tables: list[str]
    reports: list[str]


class PublishError(Exception):
    pass


def publish(settings: Settings, manifest: Manifest) -> Path:
    if manifest.status != Status.GOLD or manifest.gold_run_id is None:
        raise PublishError(f"{manifest.file_id[:12]}… is at {manifest.status}, not gold")
    target = settings.publish_root
    # Built beside the target and swapped in at the end: a crash halfway must never leave a
    # folder holding parts of two scans for a deploy to pick up.
    building = target.with_name(target.name + ".building")
    shutil.rmtree(building, ignore_errors=True)
    building.mkdir(parents=True)

    gold = settings.data_root / "gold"
    for table in TABLES:
        source = gold / table / f"file_id={manifest.file_id}" / "*.parquet"
        duckdb.execute(
            f"COPY (SELECT * FROM read_parquet('{source}', hive_partitioning=false)) "
            f"TO '{building / table}.parquet' (FORMAT PARQUET, COMPRESSION ZSTD)"
        )
    # The source path is where the file sat on our machine; the published copy ships in a
    # public image and repo, and the file id already identifies the scan.
    write_json(
        building / "manifest.json",
        manifest.model_copy(update={"source_uri": Path(manifest.source_uri).name}),
    )
    run_log = settings.data_root / "_meta" / "run" / f"{manifest.gold_run_id}.json"
    shutil.copy(run_log, building / "gold_run.json")
    # A report never run is left out, and the app shows its section as "not run".
    reports = {
        "attribution": settings.eval_root / "attribution.json",
        "finding_scores_check": settings.eval_root / "finding_scores_check.json",
        "ranking": ranking_report_path(settings.data_root, manifest.file_id),
        "llm_usage": settings.llm_usage_report,
    }
    (building / "eval").mkdir()
    copied = []
    for name, source in reports.items():
        if source.exists():
            shutil.copy(source, building / "eval" / f"{name}.json")
            copied.append(name)
    write_json(
        building / "publish.json",
        Published(
            file_id=manifest.file_id,
            data_root=str(settings.data_root),
            published_at=datetime.now(UTC),
            code_version=code_version(),
            tables=list(TABLES),
            reports=copied,
        ),
    )

    retired = target.with_name(target.name + ".old")
    shutil.rmtree(retired, ignore_errors=True)
    if target.exists():
        target.rename(retired)
    building.rename(target)
    shutil.rmtree(retired, ignore_errors=True)
    return target
