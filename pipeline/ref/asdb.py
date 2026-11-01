"""ASdb network types (asdb.stanford.edu, Stanford, IMC 2021): business type per network.

Used one way only: "ASdb says landlord" rules a network out as a company. "ASdb says
business" never promotes one, because of the top 15 networks with findings that our sources
leave unclassified and ASdb calls business, at least 9 are hosters by name (full 2026-10-26
file). Snapshots are downloaded by hand from the site into `as_of=<YYYY-MM>/`, which has no
download API; the run log records which one was read.
"""

from pathlib import Path

LANDLORD_CATEGORIES = [
    "Internet Service Provider (ISP)",
    "Phone Provider",
    "Hosting and Cloud Provider",
    "Hosting, Cloud Provider, Data Center, Server Colocation",
    "Satellite Communication",
]


def view_sql(snapshot: Path) -> str:
    """SQL creating `asdb_landlord(asn, landlord)`, one row per network ASdb lists."""
    csv = next(snapshot.glob("*_categorized_ases.csv"))
    return f"""
        CREATE TEMP TABLE asdb_raw AS SELECT * FROM read_csv('{csv}', all_varchar = true,
          header = true, null_padding = true);
        CREATE VIEW asdb_landlord AS
        SELECT "ASN" AS asn,
          bool_or(list_has_any(list_value(*COLUMNS('Layer 2$')), {LANDLORD_CATEGORIES})) AS landlord
        FROM asdb_raw GROUP BY 1;
    """
