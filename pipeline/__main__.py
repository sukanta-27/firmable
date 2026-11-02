import argparse
import json
import logging
import sys
from pathlib import Path

import duckdb

from pipeline import bronze, eval, gold, silver
from pipeline.landing import LandingError, land
from pipeline.meta import Manifest, Status, find_manifest, manifest_path, read_manifest, write_json
from pipeline.publish import PublishError, publish
from pipeline.ref import finding_scores, peeringdb, snapshot
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
    if previous and previous.status in (Status.BRONZE, Status.SILVER, Status.GOLD) and not force:
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
    if manifest.status in (Status.SILVER, Status.GOLD) and not force:
        logger.info("already in silver; pass --force to rebuild")
        return 0
    if manifest.status not in (Status.BRONZE, Status.SILVER, Status.GOLD):
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


def run_gold(source: Path, force: bool, start_at: str) -> int:
    """Build gold for one source file whose silver tables exist."""
    settings = Settings()
    manifest = find_manifest(settings.data_root, source)
    if manifest is None:
        logger.error("no manifest for %s under %s; run bronze first", source, settings.data_root)
        return 1
    if manifest.status == Status.GOLD and not force:
        logger.info("already in gold; pass --force to rebuild")
        return 0
    if manifest.status not in (Status.SILVER, Status.GOLD):
        logger.error("%s is at %s, not silver; run silver first", source, manifest.status)
        return 1

    log = gold.build(manifest, settings, start_at)
    for c in log.checks:
        mark = "ok  " if c.passed else ("FAIL" if c.blocking else "warn")
        logger.info("%s %s: %s", mark, c.name, c.detail)
    logger.info("rows %s", log.rows)
    logger.info("refs %s", log.refs)
    for name, value in sorted(log.metrics.items()):
        logger.info("metric %s = %s", name, f"{value:,.0f}")
    logger.info("seconds %s", {k: round(v, 1) for k, v in log.seconds.items()})
    final = read_manifest(settings.data_root, manifest.file_id)
    if final is None or final.status != Status.GOLD:
        logger.error("gold failed: %s", final.error if final else "no manifest")
        return 1
    return 0


def run_publish(source: Path) -> int:
    settings = Settings()
    manifest = find_manifest(settings.data_root, source)
    if manifest is None:
        logger.error("no manifest for %s under %s", source, settings.data_root)
        return 1
    try:
        target = publish(settings, manifest)
    except PublishError as e:
        logger.error("publish refused: %s", e)
        return 1
    logger.info("published %s… to %s", manifest.file_id[:12], target)
    return 0


def run_ref_peeringdb() -> int:
    try:
        target, n = peeringdb.fetch(RefSettings().ref_root)
    except (OSError, ValueError, snapshot.SnapshotError) as e:
        logger.error("peeringdb snapshot failed: %s", e)
        return 1
    logger.info("peeringdb: %s networks written to %s", f"{n:,}", target)
    return 0


def run_finding_scores(args: argparse.Namespace) -> int:
    if args.action == "render":
        target = finding_scores.render(Settings(), args.limit)
        n = len(json.loads((target / "items.json").read_text()))
        logger.info("rendered %s items to %s", n, target / "prompt.md")
        return 0
    settings = RefSettings()
    if args.action == "check":
        print("\n".join(eval.check_answers(settings)))
        return 0
    if args.action == "import":
        counts = finding_scores.import_answers(settings, args.answers, args.model, "claude_code")
    else:
        render_dir = finding_scores.newest_render(settings)
        reply = finding_scores.ANSWER_PROVIDERS["api"](settings, render_dir, args.model)
        counts = finding_scores.import_answers(settings, reply, args.model, "api", render_dir)
    logger.info("imported %s answers: %s", args.model, dict(sorted(counts.items())))
    return 0


def run_eval_ranking(source: Path) -> int:
    settings = Settings()
    manifest = find_manifest(settings.data_root, source)
    if manifest is None or manifest.status != Status.GOLD:
        logger.error("%s has no gold under %s; run gold first", source, settings.data_root)
        return 1
    print("\n".join(eval.compare_rankings(settings, manifest.file_id)))
    return 0


def run_eval_attribution(strategy: str | None) -> int:
    settings = RefSettings()
    con = duckdb.connect()
    eval.load_cases(con, settings.attribution_cases)
    report = eval.score_attribution(con, strategy or settings.attributor)
    print(f"SYNTHETIC attribution cases, strategy {report.strategy}")
    print(f"{'':34} right missed wrong")
    for name, t in [("TOTAL", report.total), *report.by_case.items()]:
        print(f"{name:34} {t.right:5} {t.missed:6} {t.wrong:5}")
    print("by confidence:")
    for level, t in report.by_confidence.items():
        print(f"  {level:32} {t.right:5} {t.missed:6} {t.wrong:5}")
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
    g = sub.add_parser("gold", help="build the gold tables for a file already in silver")
    g.add_argument("source", type=Path)
    g.add_argument("--force", action="store_true", help="rebuild even if already in gold")
    g.add_argument(
        "--from",
        dest="start_at",
        choices=gold.STEP_NAMES,
        default=gold.STEP_NAMES[0],
        help="resume a failed run at this step, reusing the outputs of the steps before it",
    )
    p = sub.add_parser("publish", help="make one file's gold the scan the app shows")
    p.add_argument("source", type=Path)
    r = sub.add_parser("ref", help="reference data: snapshots and the finding-score answers")
    r_sub = r.add_subparsers(dest="source", required=True)
    r_sub.add_parser("peeringdb", help="fetch today's PeeringDB network types")
    fs = r_sub.add_parser("finding-scores", help="the AI-answered finding-score table")
    fs_sub = fs.add_subparsers(dest="action", required=True)
    fr = fs_sub.add_parser("render", help="write the prompt for finding types with no answer")
    fr.add_argument("--limit", type=int, help="only the first N items (for a smoke test)")
    fi = fs_sub.add_parser("import", help="validate a Claude Code run's reply and store it")
    fi.add_argument("--answers", type=Path, required=True)
    fi.add_argument("--model", required=True, help="the model that wrote the reply")
    fs_sub.add_parser("check", help="compare the stored answers with KEV, EPSS and each other")
    fa = fs_sub.add_parser("ask", help="send the newest render through the API (untested)")
    fa.add_argument("--model", required=True)
    e = sub.add_parser("eval", help="measure gold against its test sets")
    e_sub = e.add_subparsers(dest="eval_target", required=True)
    ea = e_sub.add_parser("attribution", help="score attribution on the synthetic cases")
    ea.add_argument("--strategy", help="attribution strategy; default from settings")
    er = e_sub.add_parser("ranking", help="compare the company scorers on one file's gold")
    er.add_argument("source", type=Path)
    args = parser.parse_args()
    if args.step == "eval" and args.eval_target == "ranking":
        return run_eval_ranking(args.source)
    if args.step == "eval":
        return run_eval_attribution(args.strategy)
    if args.step == "ref":
        return run_ref_peeringdb() if args.source == "peeringdb" else run_finding_scores(args)
    if args.step == "publish":
        return run_publish(args.source)
    if args.step == "silver":
        return run_silver(args.source, args.force, args.start_at)
    if args.step == "gold":
        return run_gold(args.source, args.force, args.start_at)
    return run_bronze(args.source, args.force, args.start_at)


if __name__ == "__main__":
    sys.exit(main())
