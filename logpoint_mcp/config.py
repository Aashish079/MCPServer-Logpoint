"""Runtime configuration.

Every setting comes from an environment variable (or a `.env` file in the working
directory). Each integration has its own prefix, and integrations that aren't
configured are disabled: their tools are simply not registered.
"""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_COMMON = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

# A comma-separated env var (`A,B,C`) parsed into a list.
CsvList = Annotated[list[str], NoDecode]


def _split_csv(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class LogpointSettings(BaseSettings):
    """Connection to the Logpoint SIEM (Search, Incident and Alert Rule APIs)."""

    model_config = SettingsConfigDict(env_prefix="LOGPOINT_", **_COMMON)

    url: AnyHttpUrl = Field(description="Base URL of the Logpoint server, e.g. https://logpoint.example.com")
    username: str
    secret_key: SecretStr
    verify_ssl: bool = True
    ca_bundle: Path | None = Field(default=None, description="CA bundle for a private/self-signed Logpoint certificate")
    timeout_seconds: float = 30.0
    max_retries: int = 3
    api_version: str = "0.1"

    # Alert Rule (Director) API. It authenticates with a self-signed JWT instead of the secret key.
    jwt_secret: SecretStr | None = None
    jwt_subject: str | None = None
    jwt_scope: str = "alertrules:read"
    jwt_algorithm: str = "HS256"

    # Search behaviour and result size (results go into an LLM context window).
    search_timeout_seconds: float = 90.0
    max_rows: int = 500
    max_field_chars: int = 2000

    @property
    def base_url(self) -> str:
        return str(self.url).rstrip("/")

    @property
    def verify(self) -> bool | str:
        return str(self.ca_bundle) if self.ca_bundle else self.verify_ssl

    @property
    def alert_rules_enabled(self) -> bool:
        return self.jwt_secret is not None and bool(self.jwt_subject)


class ServerSettings(BaseSettings):
    """The MCP server itself."""

    model_config = SettingsConfigDict(env_prefix="MCP_", **_COMMON)

    allow_write_actions: bool = Field(
        default=False,
        description="Register tools that change Logpoint incidents or reach outside (Jira, email).",
    )
    host: str = "127.0.0.1"
    port: int = 8000
    path: str = "/mcp"
    auth_tokens: CsvList = Field(default_factory=list, description="Bearer tokens accepted on the HTTP transport")
    allow_unauthenticated: bool = False
    allowed_hosts: CsvList = Field(
        default_factory=list,
        description="Host headers accepted on the HTTP transport (DNS-rebinding protection), e.g. mcp.example.com:*",
    )
    comment_prefix: str = "[AI triage]"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["text", "json"] = "text"

    @field_validator("auth_tokens", "allowed_hosts", mode="before")
    @classmethod
    def split_csv(cls, value: object) -> object:
        return _split_csv(value)


class VirusTotalSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIRUSTOTAL_", **_COMMON)

    api_key: SecretStr | None = None
    base_url: str = "https://www.virustotal.com/api/v3"

    @property
    def enabled(self) -> bool:
        return self.api_key is not None


class AbuseIPDBSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ABUSEIPDB_", **_COMMON)

    api_key: SecretStr | None = None
    base_url: str = "https://api.abuseipdb.com/api/v2"
    max_age_days: int = 90

    @property
    def enabled(self) -> bool:
        return self.api_key is not None


class MISPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MISP_", **_COMMON)

    url: AnyHttpUrl | None = None
    api_key: SecretStr | None = None
    verify_ssl: bool = True
    max_results: int = 25

    @property
    def enabled(self) -> bool:
        return self.url is not None and self.api_key is not None


class JiraSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="JIRA_", **_COMMON)

    url: AnyHttpUrl | None = None
    email: str | None = Field(default=None, description="Jira Cloud account email; leave unset for a Data Center PAT")
    api_token: SecretStr | None = None
    project_key: str | None = None
    issue_type: str = "Task"
    labels: CsvList = Field(default_factory=lambda: ["logpoint", "soc-triage"])

    @field_validator("labels", mode="before")
    @classmethod
    def split_csv(cls, value: object) -> object:
        return _split_csv(value)

    @property
    def enabled(self) -> bool:
        return self.url is not None and self.api_token is not None and bool(self.project_key)


class SMTPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMTP_", **_COMMON)

    host: str | None = None
    port: int = 587
    username: str | None = None
    password: SecretStr | None = None
    starttls: bool = True
    use_ssl: bool = False
    timeout_seconds: float = 30.0
    from_address: str | None = None
    default_recipients: CsvList = Field(default_factory=list)
    allowed_recipients: CsvList = Field(
        default_factory=list,
        description="Addresses or @domains the server may email. Required: the LLM never picks arbitrary recipients.",
    )

    @field_validator("default_recipients", "allowed_recipients", mode="before")
    @classmethod
    def split_csv(cls, value: object) -> object:
        return _split_csv(value)

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.from_address and self.allowed_recipients)


class MitreSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MITRE_", **_COMMON)

    attack_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    cache_path: Path = Path.home() / ".cache" / "logpoint-mcp" / "enterprise-attack.json"
    cache_max_age_days: int = 30


class Settings(BaseModel):
    logpoint: LogpointSettings
    server: ServerSettings
    virustotal: VirusTotalSettings
    abuseipdb: AbuseIPDBSettings
    misp: MISPSettings
    jira: JiraSettings
    smtp: SMTPSettings
    mitre: MitreSettings

    @classmethod
    def load(cls) -> Settings:
        """Read every section from the environment. Raises pydantic.ValidationError if required values are missing."""
        return cls(
            logpoint=LogpointSettings(),
            server=ServerSettings(),
            virustotal=VirusTotalSettings(),
            abuseipdb=AbuseIPDBSettings(),
            misp=MISPSettings(),
            jira=JiraSettings(),
            smtp=SMTPSettings(),
            mitre=MitreSettings(),
        )
