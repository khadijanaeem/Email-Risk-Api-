# from pydantic_settings import BaseSettings, SettingsConfigDict

# class Settings(BaseSettings):
#     app_name: str = "Email Risk API"
#     debug: bool = True
#     database_url: str = "postgresql+psycopg://risk:risk@postgres:5432/riskdb"
#     redis_url: str = "redis://redis:6379/0"
#     api_key_prefix: str = "rk_live_"
#     cache_ttl_seconds: int = 86400

#     model_config = SettingsConfigDict(env_file=".env", extra="ignore")

# settings = Settings()

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Email Risk API"
    debug: bool = False
    database_url: str
    redis_url: str | None = None
    api_key_prefix: str = "rk_live_"
    dns_servers: str = "1.1.1.1,8.8.8.8"
    dns_timeout_seconds: float = 2.0
    dns_cache_ttl_seconds: int = 3600
    rdap_timeout_seconds: float = 3.0
    rdap_cache_ttl_seconds: int = 86400
    cors_origins: str = "http://localhost:3000"
    max_bulk_size: int = 100
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )


settings = Settings()