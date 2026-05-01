"""
Supply Chain Risk Intelligence — API Routes

Endpoints:
  POST /ingest              — Ingest CVEs from NVD API or sample data into ChromaDB
  POST /sbom/analyze        — Analyze a SBOM manifest for CVE matches and risk score
  POST /query               — Query CVE vector store for a single package
  GET  /dashboard           — Aggregate risk dashboard
  GET  /scans               — Paginated SBOM scan history
  GET  /scans/{scan_id}     — Specific scan report
  GET  /cve-stats           — CVE ingestion statistics
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query, Path, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from app.core.database import get_db, get_chroma_collection
from app.core.exceptions import ValidationException
from app.schemas.risk import (
    NVDIngestRequest, NVDIngestResponse,
    SBOMAnalysisRequest, SBOMRiskReport,
    CVEQueryRequest, CVEQueryResponse,
    Severity,
)
from app.services.nvd_ingestion_service import NVDIngestionService
from app.services.sbom_correlation_service import SBOMCorrelationService
from app.services.risk_scoring_service import RiskScoringService
from app.repositories.risk_repository import RiskRepository

limiter = Limiter(key_func=get_remote_address)
risk_router = APIRouter()


# ─── Dependency Injection ─────────────────────────────────────────────────────

async def get_repository(db: AsyncSession = Depends(get_db)) -> RiskRepository:
    return RiskRepository(db)


async def get_ingestion_service(
    repo: RiskRepository = Depends(get_repository),
) -> NVDIngestionService:
    collection = await get_chroma_collection()
    return NVDIngestionService(repo, collection)


async def get_correlation_service() -> SBOMCorrelationService:
    collection = await get_chroma_collection()
    return SBOMCorrelationService(collection)


async def get_scoring_service(
    repo: RiskRepository = Depends(get_repository),
) -> RiskScoringService:
    return RiskScoringService(repo)


# ─── Routes ───────────────────────────────────────────────────────────────────

@risk_router.post(
    "/ingest",
    response_model=NVDIngestResponse,
    summary="Ingest CVEs from NVD into ChromaDB Vector Store",
)
@limiter.limit("5/minute")
async def ingest_nvd(
    request_body: NVDIngestRequest,
    request: Request,
    service: NVDIngestionService = Depends(get_ingestion_service),
):
    """
    Fetch CVEs from NIST NVD API (or use bundled sample data) and embed them
    into ChromaDB for semantic RAG retrieval.

    **Use `use_sample_data: true`** for demo/testing without NVD API access.

    Deduplication: CVEs already in the vector store are skipped automatically.

    **Rate limit:** 5/minute (NVD API has its own rate limits)
    """
    logger.info(f"NVD ingest request | sample={request_body.use_sample_data} keyword={request_body.keyword_filter}")
    return await service.ingest(
        use_sample_data=request_body.use_sample_data,
        keyword_filter=request_body.keyword_filter,
        days_back=request_body.days_back,
        max_results=request_body.max_results,
    )


@risk_router.post(
    "/sbom/analyze",
    response_model=SBOMRiskReport,
    summary="Analyze SBOM Manifest for Supply Chain Vulnerabilities",
)
@limiter.limit("10/minute")
async def analyze_sbom(
    request_body: SBOMAnalysisRequest,
    request: Request,
    correlation_service: SBOMCorrelationService = Depends(get_correlation_service),
    scoring_service: RiskScoringService = Depends(get_scoring_service),
):
    """
    Submit a SBOM manifest (CycloneDX/SPDX/Generic) for complete supply chain risk analysis.

    **Pipeline:**
    1. Parse SBOM components
    2. Query ChromaDB (RAG) for CVE matches per component
    3. Score risk using CVSS metrics
    4. Generate LLM-powered remediation per vulnerable component
    5. Produce executive summary and overall risk score

    **Use `use_sample_data: true`** to analyze the bundled sample SBOM (no manual input needed).

    **Rate limit:** 10/minute
    """
    import json

    # Load sample SBOM if requested
    if request_body.use_sample_data:
        from app.core.config import settings
        from app.schemas.risk import SBOMManifest, SBOMMetadata, SBOMComponent, SBOMFormat
        with open(settings.SAMPLE_SBOM_PATH, "r") as f:
            raw = json.load(f)
        meta = raw.get("metadata", {}).get("component", {})
        components = [
            SBOMComponent(
                name=c["name"],
                version=c["version"],
                purl=c.get("purl"),
                description=c.get("description"),
                supplier=c.get("supplier", {}).get("name") if isinstance(c.get("supplier"), dict) else c.get("supplier"),
            )
            for c in raw.get("components", [])
        ]
        sbom = SBOMManifest(
            format=SBOMFormat.CYCLONEDX,
            metadata=SBOMMetadata(
                application_name=meta.get("name", "sample-app"),
                application_version=meta.get("version", "1.0.0"),
                supplier=meta.get("supplier", {}).get("name") if isinstance(meta.get("supplier"), dict) else None,
            ),
            components=components,
        )
    else:
        sbom = request_body.sbom

    logger.info(
        f"SBOM analysis request | app={sbom.metadata.application_name} "
        f"components={len(sbom.components)} remediation={request_body.include_remediation}"
    )

    # Step 1: RAG correlation
    correlation_results = correlation_service.correlate_sbom(sbom.components)

    # Step 2: Risk scoring + remediation
    return await scoring_service.score_sbom(
        sbom=sbom,
        correlation_results=correlation_results,
        include_remediation=request_body.include_remediation,
        severity_filter=request_body.severity_filter,
    )


@risk_router.post(
    "/query",
    response_model=CVEQueryResponse,
    summary="Query CVE Vector Store for a Single Package",
)
@limiter.limit("30/minute")
async def query_cve(
    request_body: CVEQueryRequest,
    request: Request,
    correlation_service: SBOMCorrelationService = Depends(get_correlation_service),
):
    """
    Directly query the CVE vector store for a specific package without a full SBOM.
    Useful for spot-checking individual dependencies.

    **Rate limit:** 30/minute
    """
    return correlation_service.query_package(
        package_name=request_body.package_name,
        package_version=request_body.package_version,
        top_k=request_body.top_k,
    )


@risk_router.get("/dashboard", summary="Supply Chain Risk Dashboard")
@limiter.limit("20/minute")
async def risk_dashboard(
    request: Request,
    repo: RiskRepository = Depends(get_repository),
):
    """Aggregate risk metrics across all SBOM scans and CVE ingestions."""
    dashboard = await repo.get_risk_dashboard()
    cve_stats = await repo.get_cve_stats()
    return {**dashboard, "cve_store": cve_stats}


@risk_router.get("/scans", summary="SBOM Scan History")
@limiter.limit("20/minute")
async def list_scans(
    request: Request,
    application_name: Optional[str] = Query(None, max_length=200),
    limit: int = Query(20, ge=1, le=100),
    repo: RiskRepository = Depends(get_repository),
):
    """List recent SBOM scan summaries, optionally filtered by application name."""
    scans = await repo.get_scan_history(application_name=application_name, limit=limit)
    return {
        "total_returned": len(scans),
        "scans": [
            {
                "scan_id": s.scan_id,
                "application_name": s.application_name,
                "application_version": s.application_version,
                "total_components": s.total_components,
                "vulnerable_components": s.vulnerable_components,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "overall_risk_score": s.overall_risk_score,
                "overall_severity": s.overall_severity,
                "scanned_at": s.scanned_at.isoformat(),
            }
            for s in scans
        ],
    }


@risk_router.get("/scans/{scan_id}", summary="Get Specific SBOM Scan Report")
@limiter.limit("20/minute")
async def get_scan(
    scan_id: str = Path(..., min_length=36, max_length=36),
    request: Request = None,
    repo: RiskRepository = Depends(get_repository),
):
    """Retrieve a specific SBOM scan by ID."""
    import re
    if not re.match(r'^[0-9a-f-]{36}$', scan_id):
        raise ValidationException("scan_id must be a valid UUID", fields=["scan_id"])
    scan = await repo.get_scan_by_id(scan_id)
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {
        "scan_id": scan.scan_id,
        "application_name": scan.application_name,
        "application_version": scan.application_version,
        "total_components": scan.total_components,
        "vulnerable_components": scan.vulnerable_components,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "overall_risk_score": scan.overall_risk_score,
        "overall_severity": scan.overall_severity,
        "executive_summary": scan.executive_summary,
        "scan_duration_ms": scan.scan_duration_ms,
        "scanned_at": scan.scanned_at.isoformat(),
    }


@risk_router.get("/cve-stats", summary="CVE Ingestion Statistics")
async def cve_stats(repo: RiskRepository = Depends(get_repository)):
    """Statistics on CVEs ingested into the vector store."""
    return await repo.get_cve_stats()


__all__ = ["risk_router"]
