"""Who owns an address: the business itself, or a landlord whose customers are the businesses.

Order: the scanner's own `cdn` and `cloud` tags; then `cloud` for an address on an ASN whose
addresses mostly carry the `cloud` tag, because a landlord may declare itself a business in
PeeringDB; then the network's self-declared PeeringDB type, else `unknown`. Every input is a
dated public source or a rule computed from the file; nothing here is a hand list.
"""

# A network may declare several PeeringDB types. Attribution only needs "business or
# landlord", and every ambiguous type is a landlord reading, so landlord types win.
LANDLORD_FIRST: list[tuple[str, list[str]]] = [
    ("isp", ["Cable/DSL/ISP", "NSP", "Route Server", "Route Collector"]),
    ("hosting", ["Content", "Network Services"]),
    ("edu", ["Educational/Research"]),
    ("gov", ["Government"]),
    ("enterprise", ["Enterprise", "Non-Profit"]),
]
MAPPED_TYPES = [t for _, types in LANDLORD_FIRST for t in types]


def peeringdb_class_sql(types: str) -> str:
    """SQL for the owner class of a PeeringDB `info_types` list; 'unknown' when none maps."""
    whens = " ".join(
        f"WHEN list_has_any({types}, {types_!r}) THEN '{cls}'" for cls, types_ in LANDLORD_FIRST
    )
    return f"CASE {whens} ELSE 'unknown' END"
