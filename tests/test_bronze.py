import json
from pathlib import Path

import duckdb
import pytest
import zstandard

from pipeline import bronze
from pipeline.landing import LandingError, land
from pipeline.meta import Manifest, Status, read_manifest

RECORDS = (Path(__file__).parent / "fixtures" / "records.jsonl").read_text().splitlines()


def run(tmp_path: Path, lines: list[str]) -> Manifest:
    source = tmp_path / "source.jsonl"
    source.write_text("\n".join(lines) + "\n")
    landed = land(source)
    bronze.build(landed, tmp_path / "root", max_empty_share=0.01)
    result = read_manifest(tmp_path / "root", landed.file_id)
    assert result is not None
    return result


def table(tmp_path: Path, name: str, file_id: str) -> list[tuple[object, ...]]:
    path = tmp_path / "root" / "bronze" / name / f"file_id={file_id}" / "*.parquet"
    return duckdb.execute(
        f"SELECT * FROM read_parquet('{path}', hive_partitioning=false)"
    ).fetchall()


def test_every_record_lands_once(tmp_path: Path) -> None:
    m = run(tmp_path, RECORDS)
    assert m.status == Status.BRONZE
    assert m.records == len(RECORDS)
    entries = [cve for r in RECORDS for cve in json.loads(r).get("vulns", {})]
    assert len(table(tmp_path, "vuln", m.file_id)) == len(entries)
    assert len(table(tmp_path, "cve_text", m.file_id)) == len(set(entries))


def test_cve_text_keeps_every_version_of_a_summary(tmp_path: Path) -> None:
    record = next(json.loads(r) for r in RECORDS if "vulns" in json.loads(r))
    cve = next(iter(record["vulns"]))
    variant = json.loads(json.dumps(record))
    variant["_shodan"]["id"] = "00000000-0000-0000-0000-000000000000"
    variant["vulns"] = {cve: {**record["vulns"][cve], "summary": "a different description"}}
    m = run(tmp_path, [*RECORDS, json.dumps(variant)])
    assert m.status == Status.BRONZE
    assert len([row for row in table(tmp_path, "cve_text", m.file_id) if row[0] == cve]) == 2


def test_unparseable_line_is_flagged_not_a_hollow_row(tmp_path: Path) -> None:
    # The 2026-10-26 file holds one record with a lone UTF-16 surrogate escape.
    bad = RECORDS[0].replace('"data": "', '"data": "\\ud800', 1)
    m = run(tmp_path, [*RECORDS[1:], bad])
    assert m.status == Status.BRONZE
    assert (m.records, m.unreadable) == (len(RECORDS) - 1, 1)
    path = tmp_path / "root" / "bronze" / "banner" / f"file_id={m.file_id}" / "*.parquet"
    flagged = duckdb.execute(
        f"SELECT rec_id, parse_error FROM read_parquet('{path}', hive_partitioning=false) "
        "WHERE parse_error IS NOT NULL"
    ).fetchall()
    assert flagged == [(json.loads(RECORDS[0])["_shodan"]["id"], "invalid_json")]


def test_blank_line_is_flagged(tmp_path: Path) -> None:
    m = run(tmp_path, [RECORDS[0], "", *RECORDS[1:]])
    assert (m.status, m.records, m.unreadable) == (Status.BRONZE, len(RECORDS), 1)


def test_record_missing_from_parse_fails_reconciliation(tmp_path: Path) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("\n".join(RECORDS) + "\n")
    landed = land(source)
    landed.lines += 1
    bronze.build(landed, tmp_path / "root", max_empty_share=0.01)
    m = read_manifest(tmp_path / "root", landed.file_id)
    assert m is not None and m.status == Status.FAILED
    assert m.error and "reconciliation" in m.error
    assert not (tmp_path / "root" / "bronze").exists()


def test_rerun_replaces_the_partition(tmp_path: Path) -> None:
    first = run(tmp_path, RECORDS)
    second = run(tmp_path, RECORDS)
    assert first.file_id == second.file_id
    assert len(table(tmp_path, "banner", second.file_id)) == len(RECORDS)


def test_duplicate_rec_id_fails(tmp_path: Path) -> None:
    m = run(tmp_path, [*RECORDS, RECORDS[0]])
    assert m.status == Status.FAILED
    assert m.error and "rec_id_unique" in m.error


def test_unknown_top_level_key_survives_in_extra(tmp_path: Path) -> None:
    record = json.loads(RECORDS[0])
    record["brand_new_protocol"] = {"version": "9"}
    m = run(tmp_path, [json.dumps(record), *RECORDS[1:]])
    assert m.status == Status.BRONZE
    assert m.unknown_keys == {"brand_new_protocol": 1}


def test_type_change_fails_instead_of_becoming_null(tmp_path: Path) -> None:
    record = json.loads(RECORDS[0])
    record["port"] = "443"
    m = run(tmp_path, [json.dumps(record), *RECORDS[1:]])
    assert m.status == Status.FAILED
    assert m.error and "port is not an integer" in m.error


def test_truncated_zstd_file_is_refused(tmp_path: Path) -> None:
    payload = zstandard.ZstdCompressor().compress(("\n".join(RECORDS) + "\n").encode())
    source = tmp_path / "cut.zst"
    source.write_bytes(payload[: len(payload) // 2])
    with pytest.raises(LandingError, match="mid-frame"):
        land(source)
