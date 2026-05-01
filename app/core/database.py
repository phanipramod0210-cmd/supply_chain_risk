"""
Database initialization for Supply Chain Risk Intelligence.
Manages:
  - Async PostgreSQL via SQLAlchemy 2.0
  - ChromaDB client for CVE vector embeddings
  - Redis client for NVD feed caching
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from loguru import logger
from typing import Optional

from app.core.config import settings


class Base(DeclarativeBase):
    pass


# ─── PostgreSQL ───────────────────────────────────────────────────────────────

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("SELECT 1"))
        logger.info("PostgreSQL initialized — all tables created")
    except Exception as e:
        logger.critical(f"PostgreSQL initialization failed: {e}")
        raise


# ─── ChromaDB Vector Store ────────────────────────────────────────────────────

_chroma_client: Optional[object] = None
_chroma_collection: Optional[object] = None


async def get_chroma_collection():
    """
    Returns the ChromaDB collection for NVD CVE embeddings.
    Uses get-or-create to ensure idempotency on startup.
    Falls back to in-memory client if hosted ChromaDB is unreachable.
    """
    global _chroma_client, _chroma_collection
    if _chroma_collection is not None:
        return _chroma_collection

    try:
        import chromadb
        from chromadb.config import Settings as ChromaSettings

        try:
            _chroma_client = chromadb.HttpClient(
                host=settings.CHROMA_HOST,
                port=settings.CHROMA_PORT,
                settings=ChromaSettings(anonymized_telemetry=False),
            )
            _chroma_client.heartbeat()
            logger.info(f"ChromaDB connected | host={settings.CHROMA_HOST}:{settings.CHROMA_PORT}")
        except Exception as e:
            logger.warning(f"ChromaDB remote unreachable ({e}) — falling back to in-memory client")
            _chroma_client = chromadb.Client()

        _chroma_collection = _chroma_client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(f"ChromaDB collection ready | name={settings.CHROMA_COLLECTION_NAME} count={_chroma_collection.count()}")
        return _chroma_collection

    except ImportError:
        logger.error("chromadb package not installed — RAG features unavailable")
        raise


# ─── Redis Client ─────────────────────────────────────────────────────────────

_redis_client: Optional[object] = None


async def get_redis():
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as aioredis
        _redis_client = await aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        logger.info("Redis client initialized")
    return _redis_client


async def close_connections():
    global _redis_client, _chroma_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
    logger.info("All connections closed")
