import argparse
import logging
import sys
from pathlib import Path

from pipeline import bronze, silver
from pipeline.landing import LandingError, land
from pipeline.meta import Manifest, Status, find_manifest, manifest_path, read_manifest, write_json
from pipeline.ref import peeringdb
from pipeline.settings import RefSettings, Settings

logger = logging.getLogger("pipeline")


def _landed(source: Path, data_root: Path, start_at: str) -> Manifest | None:
    """Land the file, or, when resuming past pass 1, reuse the manifest landing wrote."""
    if start_at != bronze.STEP_NAMES[0]:
        manifest = find_manifest(data_root, source)
        if manifest is None:
            logger.error("no landed manifest for %s; run without --from first", source)
        return manifest
    try:
        manifest = land(source)
    except LandingError as e:
        logger.error("landing failed: %s", e)
        return None
    logger.info(
        "landed %s: file_id=%s… lines=%s in %.1fs",
        source,
        manifest.file_id[:12],
        f"{manifest.lines:,}",
        manifest.landing_seconds,
    )
    return manifest


def run_bronze(source: Path, force: bool, start_at: str) -> int:
    """Land one source file, then build its bronze tables unless they already exist."""
    settings = Settings()
    manifest = _landed(source, settings.data_root, start_at)
    if manifest is None:
        return 1

    previous = read_manifest(settings.data_root, manifest.file_id)
    if previous and previous.status in (Status.BRONZE, Status.SILVER) and not force:
        logger.info("already in bronze; pass --force to rebuild")
        return 0
    # Recorded before parsing, so a run that dies mid-parse still leaves the hash and count.
    write_json(manifest_path(settings.data_root, manifest.file_id), manifest)

    log = bronze.build(manifest, settings.data_root, settings.max_empty_share, start_at)
    for c in log.checks:
        mark = "ok  " if c.passed else ("FAIL" if c.blocking else "warn")
        logger.info("%s %s: %s", mark, c.name, c.detail)
    logger.info("rows %s", log.rows)
    logger.info("seconds %s", {k: round(v, 1) for k, v in log.seconds.items()})
    final = read_manifest(settings.data_root, manifest.file_id)
    if final and final.status == Status.FAILED:
        logger.error("bronze failed: %s", final.error)
        return 1
    return 0


def run_silver(source: Path, force: bool, start_at: str) -> int:
    """Build silver for one source file whose bronze tables exist."""
    settings = Settings()
    manifest = find_manifest(settings.data_root, source)
    if manifest is None:
        logger.error("no manifest for %s under %s; run bronze first", source, settings.data_root)
        return 1
    if manifest.status == Status.SILVER and not force:
        logger.info("already in silver; pass --force to rebuild")
        return 0
    if manifest.status not in (Status.BRONZE, Status.SILVER):
        logger.error("%s is at %s, not bronze; run bronze first", source, manifest.status)
        return 1

    log = silver.build(manifest, settings, start_at)
    for c in log.checks:
        mark = "ok  " if c.passed else ("FAIL" if c.blocking else "warn")
        logger.info("%s %s: %s", mark, c.name, c.detail)
    logger.info("rows %s", log.rows)
    logger.info("refs %s", log.refs)
    for name, value in sorted(log.metrics.items()):
        logger.info("metric %s = %s", name, f"{value:,.0f}")
    logger.info("seconds %s", {k: round(v, 1) for k, v in log.seconds.items()})
    final = read_manifest(settings.data_root, manifest.file_id)
    if final is None or final.status != Status.SILVER:
        logger.error("silver failed: %s", final.error if final else "no manifest")
        return 1
    return 0


def run_ref_peeringdb() -> int:
    try:
        target, n = peeringdb.fetch(RefSettings().ref_root)
    except (OSError, ValueError, peeringdb.SnapshotError) as e:
        logger.error("peeringdb snapshot failed: %s", e)
        return 1
    logger.info("peeringdb: %s networks written to %s", f"{n:,}", target)
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stdout)
    parser = argparse.ArgumentParser(prog="pipeline")
    sub = parser.add_subparsers(dest="step", required=True)
    b = sub.add_parser("bronze", help="land a source file and write its bronze tables")
    b.add_argument("source", type=Path)
    b.add_argument("--force", action="store_true", help="rebuild even if already in bronze")
    b.add_argument(
        "--from",
        dest="start_at",
        choices=bronze.STEP_NAMES,
        default=bronze.STEP_NAMES[0],
        help="resume a failed run at this step, reusing the outputs of the steps before it",
    )
    s = sub.add_parser("silver", help="build the silver tables for a file already in bronze")
    s.add_argument("source", type=Path)
    s.add_argument("--force", action="store_true", help="rebuild even if already in silver")
    s.add_argument(
        "--from",
        dest="start_at",
        choices=silver.STEP_NAMES,
        default=silver.STEP_NAMES[0],
        help="resume a failed run at this step, reusing the outputs of the steps before it",
    )
    r = sub.add_parser("ref", help="fetch a reference snapshot")
    r.add_argument("source", choices=["peeringdb"])
    args = parser.parse_args()
    if args.step == "ref":
        return run_ref_peeringdb()
    if args.step == "silver":
        return run_silver(args.source, args.force, args.start_at)
    return run_bronze(args.source, args.force, args.start_at)


if __name__ == "__main__":
    sys.exit(main())
