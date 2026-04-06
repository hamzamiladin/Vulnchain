"""Application configuration loaded from environment variables."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = Field(
        default="postgresql://redteam:redteam@localhost:5432/redteam",
    )

    # Anthropic
    anthropic_api_key: str = Field(default="")

    # GitHub App
    github_app_id: int = Field(default=0)
    github_app_private_key_path: Path = Field(default=Path("./github-app.pem"))
    github_webhook_secret: str = Field(default="")

    # Agent config
    scan_sandbox_dir: Path = Field(default=Path("/tmp/redteam-scans"))
    max_repo_size_mb: int = Field(default=500)
    semgrep_timeout_seconds: int = Field(default=120)
    joern_timeout_seconds: int = Field(default=300)
    llm_model: str = Field(default="claude-sonnet-4-5")
    log_level: str = Field(default="INFO")

    # Server
    api_port: int = Field(default=8000)
    webhook_port: int = Field(default=8080)
    cors_origins: str = Field(default="http://localhost:3000")


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return cached settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
