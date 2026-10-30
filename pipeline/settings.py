from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Required, with no default: the sample is a subset of the full file, so a run that
    # silently picked a shared default root would double-count every sample record.
    data_root: Path
    max_empty_share: float = 0.01
