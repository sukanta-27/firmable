"""PeeringDB network types: a public registry where networks declare what they are.

Snapshots are written raw, one folder per UTC day, and only ever read by silver. Silver
never fetches, so a run is reproducible from the snapshot date it records.
"""

import shutil
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
import requests
from pydantic import BaseModel

URL = "https://www.peeringdb.com/api/net?fields=asn,name,info_type,info_types"
# 35,798 networks on 2026-10-30. A response far below that is an error page or a truncated
# list, and would silently turn most networks `unknown`.
MIN_NETWORKS = 20_000


class Network(BaseModel):
    asn: int
    name: str
    info_type: str
    info_types: list[str]


class Response(BaseModel):
    data: list[Network]


class SnapshotError(Exception):
    pass


def fetch(ref_root: Path) -> tuple[Path, int]:
    """Download every network's type and write today's snapshot, replacing today's earlier one."""
    response = requests.get(URL, timeout=300)
    response.raise_for_status()
    networks = Response.model_validate_json(response.content).data
    if len(networks) < MIN_NETWORKS:
        raise SnapshotError(f"only {len(networks)} networks; expected at least {MIN_NETWORKS}")

    target = ref_root / "peeringdb" / f"as_of={datetime.now(UTC).date()}"
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=target.parent))
    try:
        rows = work / "networks.jsonl"
        rows.write_text("\n".join(n.model_dump_json() for n in networks) + "\n")
        (work / "data").mkdir()
        # Bronze stores the ASN as text like AS15169; matching that here keeps the join plain.
        duckdb.execute(
            f"""COPY (
              SELECT 'AS' || asn AS asn, name, nullif(info_type, '') AS info_type, info_types
              FROM read_json('{rows}', columns = {{
                asn: 'BIGINT', name: 'VARCHAR', info_type: 'VARCHAR', info_types: 'VARCHAR[]'
              }})
            ) TO '{work / "data" / "networks.parquet"}' (FORMAT PARQUET)"""
        )
        shutil.rmtree(target, ignore_errors=True)
        (work / "data").rename(target)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return target, len(networks)


def newest(ref_root: Path) -> tuple[Path, date]:
    """The latest snapshot folder and its date."""
    found = sorted((ref_root / "peeringdb").glob("as_of=*"))
    if not found:
        raise SnapshotError(
            f"no PeeringDB snapshot under {ref_root}; run `pipeline ref peeringdb` first"
        )
    return found[-1], date.fromisoformat(found[-1].name.removeprefix("as_of="))
