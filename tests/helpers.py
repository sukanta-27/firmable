import json
from pathlib import Path
from typing import Any

import duckdb

from pipeline import bronze, silver
from pipeline.landing import land
from pipeline.meta import Manifest, Status, read_manifest
from pipeline.settings import Settings


def variant(line: str, n: int, **changes: Any) -> str:
    record = json.loads(line)
    record["_shodan"]["id"] = f"00000000-0000-0000-0000-{n:012d}"
    record.update(changes)
    return json.dumps(record)


def run(
    root: Path,
    lines: list[str],
    networks: list[tuple[str, list[str]]] | None = None,
    **settings_overrides: Any,
) -> Manifest:
    """Land, bronze and silver a source file under `root`, with a tiny PeeringDB snapshot."""
    root.mkdir(parents=True, exist_ok=True)
    snapshot = root / "ref" / "peeringdb" / "as_of=2026-10-30"
    snapshot.mkdir(parents=True, exist_ok=True)
    rows = networks or [("AS0", ["NSP"])]
    duckdb.execute(
        "COPY (SELECT unnest($asns) AS asn, 'net' AS name, NULL::VARCHAR AS info_type, "
        f"unnest($types) AS info_types) TO '{snapshot / 'data.parquet'}' (FORMAT PARQUET)",
        {"asns": [a for a, _ in rows], "types": [t for _, t in rows]},
    )
    source = root / "source.jsonl"
    source.write_text("\n".join(lines) + "\n")
    landed = land(source)
    settings = Settings(data_root=root / "data", ref_root=root / "ref", **settings_overrides)
    bronze.build(landed, settings.data_root, max_empty_share=0.01)
    in_bronze = read_manifest(settings.data_root, landed.file_id)
    assert in_bronze is not None and in_bronze.status == Status.BRONZE
    silver.build(in_bronze, settings)
    result = read_manifest(settings.data_root, landed.file_id)
    assert result is not None
    assert result.status == Status.SILVER, result.error
    return result


def table(root: Path, name: str, columns: str = "*", where: str = "true") -> list[tuple[Any, ...]]:
    path = root / "data" / "silver" / name / "*" / "*.parquet"
    return duckdb.execute(
        f"SELECT {columns} FROM read_parquet('{path}', hive_partitioning=false) WHERE {where} "
        "ORDER BY ALL"
    ).fetchall()
