"""Staging, resume, memory sampling and publish, shared by every layer.

A layer is an ordered list of steps, each writing one or more tables into a staging folder.
Published partitions change only when every blocking check passes, so a failed run never
leaves half a file in a layer. A failed run keeps the outputs of the steps that finished,
so `start_at` can resume from the step that failed instead of redoing the whole file.
"""

import logging
import resource
import shutil
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import duckdb

from pipeline.meta import Check, RunLog

SAMPLE_SECONDS = 10
# Measured on a 2M-line slice of the 2026-10-26 file: bronze pass 1 peaked at 17.1 GB of
# DuckDB memory with 12 threads (limit 19.1 GiB) and 11.1 GB with 8, at the same speed.
THREADS = 8

logger = logging.getLogger("pipeline.stage")

type Step[C] = Callable[[duckdb.DuckDBPyConnection, C, Path], None]
type Checks = Callable[[duckdb.DuckDBPyConnection, Path, dict[str, int]], list[Check]]


def read(staging: Path, table: str) -> str:
    return f"read_parquet('{staging / table}/*.parquet', hive_partitioning=false)"


def copy(con: duckdb.DuckDBPyConnection, query: str, target: Path, options: str = "") -> None:
    """Write a query's result to Parquet."""
    con.execute(f"COPY ({query}) TO '{target}' (FORMAT PARQUET, COMPRESSION ZSTD{options})")


def run[C](
    log: RunLog,
    data_root: Path,
    layer: str,
    steps: list[tuple[str, Step[C], tuple[str, ...]]],
    context: C,
    start_at: str,
    checks: Checks,
    setup_sql: str = "",
    unpublished: tuple[str, ...] = (),
) -> str | None:
    """Run the steps into staging, check, then publish. Returns the error, or None.

    Tables in `unpublished` are intermediates: checked and counted, then dropped with staging.
    """
    names = [name for name, _, _ in steps]
    tables = [t for _, _, ts in steps for t in ts]
    staging = data_root / "_staging" / layer / log.file_id
    spill = staging / "_spill"
    first = names.index(start_at)
    if first == 0:
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    for _, _, done in steps[:first]:
        missing = [t for t in done if not (staging / t).exists()]
        if missing:
            return f"cannot resume at {start_at}: no {missing}"

    con = duckdb.connect()
    con.execute("SET preserve_insertion_order = false")
    con.execute(f"SET threads = {THREADS}")
    con.execute(f"SET temp_directory = '{spill}'")
    if setup_sql:
        con.execute(setup_sql)
    current = start_at
    try:
        for name, step, outputs in steps[first:]:
            current = name
            for table in outputs:
                shutil.rmtree(staging / table, ignore_errors=True)
            with watched(con, name, spill, log):
                step(con, context, staging)

        current = "checks"
        started = time.time()
        for table in tables:
            n = con.execute(f"SELECT count(*) FROM {read(staging, table)}").fetchone()
            log.rows[table] = n[0] if n else 0
        log.checks = checks(con, staging, log.rows)
        log.seconds["checks"] = time.time() - started
    except duckdb.Error as e:
        if current in names:
            logger.error("staging kept; resume with --from %s", current)
        return f"{current}: {e}"
    finally:
        con.close()
        shutil.rmtree(spill, ignore_errors=True)

    failed = [c for c in log.checks if c.blocking and not c.passed]
    if failed:
        logger.error("checks failed; staging kept at %s for inspection", staging)
        return "; ".join(f"{c.name}: {c.detail}" for c in failed)

    for table in (t for t in tables if t not in unpublished):
        final = data_root / layer / table / f"file_id={log.file_id}"
        shutil.rmtree(final, ignore_errors=True)
        final.parent.mkdir(parents=True, exist_ok=True)
        (staging / table).rename(final)
    shutil.rmtree(staging, ignore_errors=True)
    return None


def _dir_bytes(path: Path) -> int:
    """Total size of the files under a folder; 0 if it does not exist."""
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.exists() else 0


def _process_peak_gb() -> float:
    """Highest memory this process has used so far, across all steps."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is in bytes on macOS and in kilobytes on Linux.
    return peak / 1e9 if sys.platform == "darwin" else peak / 1e6


@contextmanager
def watched(con: duckdb.DuckDBPyConnection, step: str, spill: Path, log: RunLog) -> Iterator[None]:
    """Time a step and sample DuckDB memory and spill size while it runs.

    A sample is logged every SAMPLE_SECONDS and the step's peaks go into the run log, so
    a slow or failing step shows where its memory went instead of failing silently.
    """
    probe = con.cursor()
    peaks = {"duckdb_gb": 0.0, "spill_gb": 0.0}
    stop = threading.Event()
    started = time.time()

    def sample() -> None:
        while not stop.wait(SAMPLE_SECONDS):
            by_tag = probe.execute(
                "SELECT tag, memory_usage_bytes FROM duckdb_memory() ORDER BY 2 DESC"
            ).fetchall()
            duckdb_gb = sum(b for _, b in by_tag) / 1e9
            spill_gb = _dir_bytes(spill) / 1e9
            peaks["duckdb_gb"] = max(peaks["duckdb_gb"], duckdb_gb)
            peaks["spill_gb"] = max(peaks["spill_gb"], spill_gb)
            top = ", ".join(f"{tag} {b / 1e9:.1f}" for tag, b in by_tag[:3] if b)
            logger.info(
                "%s %4.0fs: duckdb %.1f GB [%s], spill %.1f GB, process peak %.1f GB",
                step,
                time.time() - started,
                duckdb_gb,
                top,
                spill_gb,
                _process_peak_gb(),
            )

    sampler = threading.Thread(target=sample, daemon=True)
    logger.info("%s started", step)
    sampler.start()
    try:
        yield
    finally:
        stop.set()
        sampler.join()
        probe.close()
        log.seconds[step] = time.time() - started
        log.peaks[step] = {**peaks, "process_peak_gb": _process_peak_gb()}
        logger.info("%s ended after %.1fs; peaks %s", step, log.seconds[step], log.peaks[step])
