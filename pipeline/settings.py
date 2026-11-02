from pathlib import Path

from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings


class Price(BaseModel):
    input_per_mtok: float
    output_per_mtok: float
    # Haiku 5.5 charges more per token above 100K input tokens; past this the row prices
    # nothing rather than under-price.
    up_to_input_tokens: int | None = None


class RefSettings(BaseSettings):
    """What works without a dataset: reference snapshots, the finding-score answers and the
    synthetic eval. Split out so those commands do not demand a DATA_ROOT."""

    # Outside every data root: the sample and full datasets share one snapshot.
    ref_root: Path = Path("data/ref")
    attributor: str = "rules_ab_v1"
    attribution_cases: Path = Path("tests/eval/attribution_cases.json")
    # Committed: written only by `pipeline ref finding-scores import`, never by hand.
    answers_path: Path = Path("finding_scores/answers.jsonl")
    # The model whose answers gold scores with; every other model's are a second opinion.
    # It calls no model, so it is not finding_scores_model: switching gold to another
    # model's answers re-scores every company and is decided after `check`, not by default.
    answers_model: str = "claude-opus-5-5"
    # The model `ask` sends the prompt to. The API key works only for Haiku.
    finding_scores_model: str = "claude-haiku-5-5"
    # Committed, so a cost quoted in the write-up points at a file in git.
    llm_usage_path: Path = Path("llm_usage/calls.jsonl")
    llm_usage_report: Path = Path("llm_usage/summary.json")
    llm_prices: dict[str, Price] = {
        "claude-haiku-5-5": Price(
            input_per_mtok=0.10, output_per_mtok=0.50, up_to_input_tokens=100_000
        ),
        "claude-opus-5-5": Price(input_per_mtok=4.00, output_per_mtok=20.00),
        "claude-sonnet-5-5": Price(input_per_mtok=2.00, output_per_mtok=10.00),
    }
    llm_price_source: str = (
        "claude-api skill model table, cached 2026-10-06; not yet checked on Anthropic's "
        "pricing page"
    )
    prompt_version: str = "v1"
    finding_scorer: str = "ssvc_v1"
    kev_path: Path = Path("data/external/kev.json")
    epss_path: Path = Path("data/external/epss_scores-current.csv.gz")
    # Only the untested `ask` command uses it; None lets the SDK find its own credentials.
    anthropic_api_key: SecretStr | None = None


class Settings(RefSettings):
    # Required, with no default: the sample is a subset of the full file, so a run that
    # silently picked a shared default root would double-count every sample record.
    data_root: Path
    # Outside every data root: it holds the one scan the app shows, whichever root it came from.
    publish_root: Path = Path("data/publish")
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
