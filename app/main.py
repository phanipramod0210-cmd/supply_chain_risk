"""
POC-04: Supply Chain Risk Intelligence
RAG pipeline that ingests NVD CVE feeds and correlates them with vendor SBOMs.
"""
from contextlib import asynccontextmanager
import time
import uuid
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from app.core.config import settings
from app.core.exceptions import (
    SupplyChainException, ValidationException,
    NVDFetchException, SBOMParseException, RAGException,
    RiskScoringException, RepositoryException,
)
from app.core.database import init_db, close_connections
from app.api.routes import risk_router


def setup_logging():
    logger.remove()
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:<8}</level> | <cyan>{name}</cyan>:{function} - <level>{message}</level>",
        level="INFO",
        colorize=True,
    )
    logger.add(
        "logs/supply_chain_{time}.log",
        rotation="100 MB",
        retention="30 days",
        level="DEBUG",
        serialize=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Supply Chain Risk Intelligence starting up")
    await init_db()
    logger.info("PostgreSQL ready. Attempting ChromaDB connection...")
    try:
        from app.core.database import get_chroma_collection
        collection = await get_chroma_collection()
        logger.info(f"ChromaDB ready | collection_size={collection.count()} CVEs indexed")
    except Exception as e:
        logger.warning(f"ChromaDB not yet available ({e}) — run /ingest to populate")
    logger.info("Supply Chain Risk Intelligence ready")
    yield
    await close_connections()
    logger.info("Supply Chain Risk Intelligence shut down")


app = FastAPI(
    title="Supply Chain Risk Intelligence",
    description=(
        "RAG-powered pipeline that ingests NVD CVE feeds into ChromaDB "
        "and correlates them with vendor SBOM manifests to produce "
        "actionable risk reports with CVSS-based scoring and LLM remediation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start = time.time()
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    logger.info(f"→ {request.method} {request.url.path} | req_id={request_id[:8]}")
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)
    logger.info(f"← {response.status_code} | req_id={request_id[:8]} ms={duration_ms}")
    response.headers["X-Request-Duration-Ms"] = str(duration_ms)
    return response


# ─── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(ValidationException)
async def validation_handler(request: Request, exc: ValidationException):
    return JSONResponse(
        status_code=422,
        content={"error": exc.detail, "code": exc.error_code, "fields": exc.fields},
    )


@app.exception_handler(NVDFetchException)
async def nvd_fetch_handler(request: Request, exc: NVDFetchException):
    logger.error(f"NVD fetch error: {exc.detail}")
    return JSONResponse(
        status_code=503,
        content={"error": exc.detail, "code": exc.error_code},
    )


@app.exception_handler(SBOMParseException)
async def sbom_parse_handler(request: Request, exc: SBOMParseException):
    logger.warning(f"SBOM parse error: {exc.detail}")
    return JSONResponse(
        status_code=400,
        content={"error": exc.detail, "code": exc.error_code, "component": exc.component},
    )


@app.exception_handler(RAGException)
async def rag_handler(request: Request, exc: RAGException):
    logger.error(f"RAG error [{exc.operation}]: {exc.detail}")
    return JSONResponse(
        status_code=503,
        content={"error": exc.detail, "code": exc.error_code, "operation": exc.operation},
    )


@app.exception_handler(RiskScoringException)
async def scoring_handler(request: Request, exc: RiskScoringException):
    logger.error(f"Risk scoring error: {exc.detail}")
    return JSONResponse(
        status_code=503,
        content={"error": exc.detail, "code": exc.error_code},
    )


@app.exception_handler(RepositoryException)
async def repo_handler(request: Request, exc: RepositoryException):
    logger.error(f"Repository error: {exc.detail}")
    return JSONResponse(
        status_code=500,
        content={"error": exc.detail, "code": exc.error_code},
    )


@app.exception_handler(SupplyChainException)
async def sc_handler(request: Request, exc: SupplyChainException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "code": exc.error_code},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.critical(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "INTERNAL_ERROR"},
    )


app.include_router(risk_router, prefix="/api/v1/risk", tags=["Supply Chain Risk"])


@app.get("/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "service": "supply-chain-risk-intelligence",
        "version": "1.0.0",
    }
