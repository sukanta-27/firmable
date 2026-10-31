from pathlib import Path

from pydantic_settings import BaseSettings


class RefSettings(BaseSettings):
    """What reference snapshots need. Split out so fetching one does not demand a DATA_ROOT."""

    # Outside every data root: the sample and full datasets share one snapshot.
    ref_root: Path = Path("data/ref")


class Settings(RefSettings):
    # Required, with no default: the sample is a subset of the full file, so a run that
    # silently picked a shared default root would double-count every sample record.
    data_root: Path
    max_empty_share: float = 0.01
    # Distinct port + transport pairs above which an address is labelled answers_everything.
    # 99.9% of non-CDN, non-honeypot addresses answer on 62 or fewer (2026-10-26 file).
    answers_everything_ports: int = 50
    # Thresholds below come from the archived analysis and were not re-tested.
    ip_number_min_addresses: int = 5
    ip_number_min_share: float = 0.5
    network_domain_min_records: int = 50
    network_domain_min_share: float = 0.3
    # An ASN whose addresses are mostly tagged cloud (not cdn) is a cloud landlord even where
    # the scanner left an address untagged. Assumed cut-offs: on the 2026-10-26 file only 4
    # ASNs with 100+ addresses have a share between 10% and 50%, so any cut in that band
    # moves only those.
    asn_cloud_min_share: float = 0.5
    asn_cloud_min_addresses: int = 100
