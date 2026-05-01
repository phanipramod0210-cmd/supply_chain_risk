"""POC-04: Supply Chain Risk Intelligence — Configuration"""
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    # API
    ALLOWED_ORIGINS: List[str] = ["*"]
    API_RATE_LIMIT: str = "20/minute"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sc_user:sc_pass@postgres:5432/supplychain_db"

    # Redis
    REDIS_URL: str = "redis://:sc_redis_pass@redis:6379/0"
    NVD_CACHE_TTL_SECONDS: int = 3600

    # ChromaDB (Vector Store)
    CHROMA_HOST: str = "chromadb"
    CHROMA_PORT: int = 8000
    CHROMA_COLLECTION_NAME: str = "nvd_cve_embeddings"

    # LLM
    ANTHROPIC_API_KEY: str = ""
    LLM_MODEL: str = "claude-3-5-sonnet-20241022"
    LLM_MAX_TOKENS: int = 2048
    LLM_TIMEOUT_SECONDS: int = 45
    LLM_RETRY_ATTEMPTS: int = 3

    # NVD Feed
    NVD_API_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = ""           # Optional — raises rate limit from 5/30s to 50/30s
    NVD_RESULTS_PER_PAGE: int = 100
    NVD_REQUEST_TIMEOUT: int = 30

    # Risk Scoring
    CVSS_CRITICAL_THRESHOLD: float = 9.0
    CVSS_HIGH_THRESHOLD: float = 7.0
    CVSS_MEDIUM_THRESHOLD: float = 4.0
    MAX_SBOM_COMPONENTS: int = 1000
    RAG_TOP_K: int = 5              # CVEs to retrieve per SBOM component
    RAG_SIMILARITY_THRESHOLD: float = 0.6

    # Sample data paths
    SAMPLE_NVD_FEED_PATH: str = "data/sample_nvd_feed.json"
    SAMPLE_SBOM_PATH: str = "data/sample_sbom.json"

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
