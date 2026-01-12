"""API Configuration settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings


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

    # Neo4j Settings
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "cloudsecurity"

    # Logging Settings
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "text"

    # Graceful Shutdown Settings
    shutdown_timeout: int = 30  # seconds to wait for in-flight requests

    # Rate Limiting Settings
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    rate_limit_burst: int = 20

    # Security Settings - CORS
    # For production, set API_CORS_ORIGINS to specific trusted domains only
    # Example: "https://yourdomain.com,https://app.yourdomain.com"

    # Paths
    reports_dir: str = "/reports"
    docker_compose_file: str = "../docker-compose.yml"

    @property
    def database_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins into list."""
        return [origin.strip() for origin in self.api_cors_origins.split(",")]

    class Config:
        env_prefix = ""
        case_sensitive = False
        # Support both with and without prefix
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
