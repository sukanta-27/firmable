import argparse
import logging
import sys
from pathlib import Path

from pipeline import bronze
from pipeline.landing import LandingError, land
from pipeline.meta import Manifest, Status, find_manifest, manifest_path, read_manifest, write_json
from pipeline.settings import Settings

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
    if previous and previous.status == Status.BRONZE and not force:
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
    args = parser.parse_args()
    return run_bronze(args.source, args.force, args.start_at)


if __name__ == "__main__":
    sys.exit(main())
