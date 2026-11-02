from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    """The app's settings, apart from the pipeline's: the pipeline requires a data root, and
    the app only ever reads the one published scan."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    publish_root: Path = Path("data/publish")
    company_scorer: str = "worst_x_confidence_v1"
    # Username to argon2 hash, as JSON. Hashes are full of `$`: single-quote the value in
    # .env and in the shell, or the shell expands them.
    app_users: dict[str, str] = {}
    session_secret: SecretStr
    session_hours: int = 12
    # Off only for local http: browsers drop a Secure cookie that arrives over plain http.
    cookie_secure: bool = True
    # Assumed, not tuned: enough for a reviewer's typos, too few for guessing.
    login_max_failures: int = 10
    login_window_minutes: int = 15
