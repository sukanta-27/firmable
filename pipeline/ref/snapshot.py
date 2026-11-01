from pathlib import Path


class SnapshotError(Exception):
    pass


def newest(ref_root: Path, source: str) -> tuple[Path, str]:
    """The latest `as_of=` folder of a reference source, and its as-of label.

    The label is text because sources date differently: PeeringDB by day, ASdb by month.
    """
    found = sorted((ref_root / source).glob("as_of=*"))
    if not found:
        raise SnapshotError(f"no {source} snapshot under {ref_root}")
    return found[-1], found[-1].name.removeprefix("as_of=")
