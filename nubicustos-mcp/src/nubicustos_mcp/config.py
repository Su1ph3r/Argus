"""Configuration management for Nubicustos MCP Server."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class MCPSettings(BaseSettings):
    """MCP Server configuration loaded from environment variables."""

    # Nubicustos API connection
    api_url: str = "http://localhost:8000"
    api_key: str | None = None

    # Request settings
    request_timeout: int = 30
    max_retries: int = 3

    # MCP server metadata
    server_name: str = "Nubicustos MCP Server"
    server_version: str = "1.0.0"

    model_config = SettingsConfigDict(
        env_prefix="NUBICUSTOS_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# Global settings instance
settings = MCPSettings()
