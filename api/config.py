"""API Configuration settings."""
import os
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_key: str = ""
    api_cors_origins: str = "http://localhost:8080,http://localhost:3000"
    debug: bool = False

    # Database Settings
    db_host: str = "postgresql"
    db_port: int = 5432
    db_name: str = "security_audits"
    db_user: str = "auditor"
    db_password: str = "changeme"

    # Paths
    reports_dir: str = "/reports"
    docker_compose_file: str = "../docker-compose.yml"

    @property
    def database_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def cors_origins_list(self) -> list:
        """Parse CORS origins into list."""
        return [origin.strip() for origin in self.api_cors_origins.split(",")]

    class Config:
        env_prefix = ""
        case_sensitive = False
        # Support both with and without prefix
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
