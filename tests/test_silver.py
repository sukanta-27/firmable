import json
import random
from pathlib import Path
from typing import Any

import duckdb

from pipeline import bronze, silver
from pipeline.landing import land
from pipeline.meta import Manifest, Status, read_manifest
from pipeline.settings import Settings

RECORDS = (Path(__file__).parent / "fixtures" / "records.jsonl").read_text().splitlines()
NGINX = next(r for r in RECORDS if '"d767b4f6' in r)
WITH_CVES = next(r for r in RECORDS if '"cfb933d2' in r)
UNTAGGED = next(r for r in RECORDS if '"633ccbc2' in r)


def variant(line: str, n: int, **changes: Any) -> str:
    record = json.loads(line)
    record["_shodan"]["id"] = f"00000000-0000-0000-0000-{n:012d}"
    record.update(changes)
    return json.dumps(record)


def run(
    root: Path, lines: list[str], networks: list[tuple[str, list[str]]] | None = None
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
    settings = Settings(data_root=root / "data", ref_root=root / "ref")
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


def test_dedupe_folds_repeat_sightings_and_loses_no_record(tmp_path: Path) -> None:
    later = variant(NGINX, 1, timestamp="2026-10-26T13:00:00.000000")
    run(tmp_path, [*RECORDS, later])
    services = table(tmp_path, "service", "sightings")
    assert len(services) == len(RECORDS)
    assert sum(n for (n,) in services) == len(RECORDS) + 1


def test_finding_seen_in_one_sighting_survives_dedupe(tmp_path: Path) -> None:
    earlier_id = json.loads(WITH_CVES)["_shodan"]["id"]
    later = variant(WITH_CVES, 1, timestamp="2026-10-26T13:00:00.000000", vulns={}, hostnames=[])
    run(tmp_path, [*RECORDS, later])
    (key,) = table(tmp_path, "service", "service_key", "sightings = 2")[0]
    vuln_ids = table(tmp_path, "service_vuln", "DISTINCT rec_id", f"service_key = '{key}'")
    clue_ids = table(tmp_path, "identity_evidence", "DISTINCT rec_id", f"service_key = '{key}'")
    assert vuln_ids == clue_ids == [(earlier_id,)]
    assert len(table(tmp_path, "service_vuln", where=f"service_key = '{key}'")) == 8


def test_honeypot_address_labels_every_service_on_it(tmp_path: Path) -> None:
    decoy = variant(UNTAGGED, 1, port=8073, tags=["honeypot"])
    run(tmp_path, [*RECORDS, decoy])
    ip = json.loads(UNTAGGED)["ip_str"]
    assert table(tmp_path, "service", "port, noise_reason", f"ip = '{ip}'") == [
        (8072, "honeypot"),
        (8073, "honeypot"),
    ]


def test_keys_and_shown_row_are_stable_across_reruns_and_input_order(tmp_path: Path) -> None:
    # Same service, same timestamp, both with a product: only rec_id can break the tie.
    tied = [variant(NGINX, n, timestamp="2026-10-26T13:00:00.000000") for n in (1, 2)]
    lines = [*RECORDS, *tied]
    shuffled = lines[:]
    random.Random(7).shuffle(shuffled)
    columns = "service_key, shown_rec_id"

    run(tmp_path / "a", lines)
    first = table(tmp_path / "a", "service", columns)
    run(tmp_path / "a", lines)
    run(tmp_path / "b", shuffled)

    assert table(tmp_path / "a", "service", columns) == first
    assert table(tmp_path / "b", "service", columns) == first
    assert ("00000000-0000-0000-0000-000000000002",) in table(
        tmp_path / "a", "service", "shown_rec_id"
    )


def test_platform_name_is_infrastructure_unless_a_customer_domain_is_inside(
    tmp_path: Path,
) -> None:
    # Both names are from the 2M-line slice of the 2026-10-26 file.
    names = ["d3o7okqs1lmm3v.cloudfront.net", "www.btig.com.cdn.cloudflare.net"]
    run(tmp_path, [variant(UNTAGGED, 1, hostnames=names), *RECORDS])
    assert table(
        tmp_path,
        "identity_evidence",
        "raw_value, normalized_value, is_infrastructure, infra_reason",
        f"raw_value IN {tuple(names)}",
    ) == [
        ("d3o7okqs1lmm3v.cloudfront.net", "cloudfront.net", True, "platform_domain"),
        ("www.btig.com.cdn.cloudflare.net", "btig.com", False, None),
    ]


def test_network_with_several_peeringdb_types_takes_the_landlord_class(tmp_path: Path) -> None:
    asn = json.loads(UNTAGGED)["asn"]
    run(tmp_path, RECORDS, networks=[(asn, ["Enterprise", "Content"])])
    ip = json.loads(UNTAGGED)["ip_str"]
    assert table(tmp_path, "address", "owner_class, owner_class_source", f"ip = '{ip}'") == [
        ("hosting", "peeringdb")
    ]
