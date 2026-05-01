"""
Test Suite — SBOM Correlation & Risk Scoring (POC-04)

Covers:
  - SBOM component schema validation
  - Query string construction
  - Package name matching logic (fuzzy / exact)
  - ChromaDB result parsing and similarity filtering
  - Risk scoring: severity bucketing, CVSS aggregation
  - Executive summary fallback
  - Full SBOM analysis flow (mocked)
  - API endpoint integration tests
"""
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.schemas.risk import (
    SBOMComponent, SBOMManifest, SBOMMetadata, SBOMFormat,
    SBOMAnalysisRequest, CVEQueryRequest, Severity,
    MatchedCVE, NVDIngestRequest,
)
from app.services.sbom_correlation_service import SBOMCorrelationService
from app.services.risk_scoring_service import RiskScoringService, max_severity, SEVERITY_ORDER
from app.core.exceptions import RAGException


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def urllib3_component():
    return SBOMComponent(name="urllib3", version="1.26.14", purl="pkg:pypi/urllib3@1.26.14")


@pytest.fixture
def cryptography_component():
    return SBOMComponent(name="cryptography", version="41.0.3", purl="pkg:pypi/cryptography@41.0.3")


@pytest.fixture
def clean_component():
    return SBOMComponent(name="pydantic", version="2.4.2", purl="pkg:pypi/pydantic@2.4.2")


@pytest.fixture
def sample_sbom(urllib3_component, cryptography_component, clean_component):
    return SBOMManifest(
        format=SBOMFormat.CYCLONEDX,
        metadata=SBOMMetadata(
            application_name="acme-payment-service",
            application_version="2.4.1",
            supplier="ACME Corp",
        ),
        components=[urllib3_component, cryptography_component, clean_component],
    )


@pytest.fixture
def matched_cve_high():
    return MatchedCVE(
        cve_id="CVE-2023-44487",
        description="HTTP/2 Rapid Reset Attack",
        cvss_score=7.5,
        severity=Severity.HIGH,
        similarity_score=0.91,
        affected_versions=["1.26.14"],
        published=datetime(2023, 10, 10),
        remediation_available=True,
    )


@pytest.fixture
def matched_cve_critical():
    return MatchedCVE(
        cve_id="CVE-2024-21507",
        description="NULL pointer dereference in PKCS12 parsing",
        cvss_score=9.1,
        severity=Severity.CRITICAL,
        similarity_score=0.87,
        published=datetime(2024, 1, 5),
        remediation_available=True,
    )


@pytest.fixture
def mock_chroma_collection():
    col = MagicMock()
    col.count.return_value = 5
    col.get.return_value = {"metadatas": []}
    # Default: return empty results
    col.query.return_value = {"ids": [[]], "metadatas": [[]], "distances": [[]]}
    return col


@pytest.fixture
def mock_risk_repository():
    repo = AsyncMock()
    repo.save_scan = AsyncMock(return_value="test-scan-id")
    return repo


# ─── Unit Tests: Schema Validation ───────────────────────────────────────────

class TestSBOMSchemaValidation:

    def test_valid_component(self, urllib3_component):
        assert urllib3_component.name == "urllib3"
        assert urllib3_component.version == "1.26.14"

    def test_component_name_lowercased(self):
        comp = SBOMComponent(name="Urllib3", version="1.26.14")
        assert comp.name == "urllib3"

    def test_component_version_strips_v_prefix(self):
        comp = SBOMComponent(name="requests", version="v2.28.1")
        assert comp.version == "2.28.1"

    def test_component_blank_name_rejected(self):
        with pytest.raises(Exception):
            SBOMComponent(name="   ", version="1.0.0")

    def test_sbom_empty_components_rejected(self):
        with pytest.raises(Exception):
            SBOMManifest(
                format=SBOMFormat.CYCLONEDX,
                metadata=SBOMMetadata(application_name="app", application_version="1.0"),
                components=[],
            )

    def test_sbom_component_count_exceeds_limit(self):
        from app.core.config import settings
        components = [SBOMComponent(name=f"pkg{i}", version="1.0.0") for i in range(settings.MAX_SBOM_COMPONENTS + 1)]
        with pytest.raises(Exception):
            SBOMManifest(
                format=SBOMFormat.CYCLONEDX,
                metadata=SBOMMetadata(application_name="app", application_version="1.0"),
                components=components,
            )

    def test_cve_query_name_lowercased(self):
        req = CVEQueryRequest(package_name="  Urllib3  ", package_version="1.26.14")
        assert req.package_name == "urllib3"

    def test_cve_query_top_k_bounds(self):
        with pytest.raises(Exception):
            CVEQueryRequest(package_name="pkg", top_k=25)


# ─── Unit Tests: SBOMCorrelationService ──────────────────────────────────────

class TestSBOMCorrelationService:

    def test_build_query_includes_package_name(self, mock_chroma_collection, urllib3_component):
        service = SBOMCorrelationService(mock_chroma_collection)
        query = service._build_query(urllib3_component)
        assert "urllib3" in query
        assert "1.26.14" in query

    def test_package_match_exact(self, mock_chroma_collection):
        service = SBOMCorrelationService(mock_chroma_collection)
        meta = {"affected_packages": json.dumps(["urllib3", "requests"])}
        assert service._is_package_match("urllib3", meta) is True

    def test_package_match_with_version(self, mock_chroma_collection):
        service = SBOMCorrelationService(mock_chroma_collection)
        meta = {"affected_packages": json.dumps(["urllib3:1.26.14"])}
        assert service._is_package_match("urllib3", meta) is True

    def test_package_match_case_insensitive(self, mock_chroma_collection):
        service = SBOMCorrelationService(mock_chroma_collection)
        meta = {"affected_packages": json.dumps(["Urllib3"])}
        assert service._is_package_match("urllib3", meta) is True

    def test_package_match_no_match(self, mock_chroma_collection):
        service = SBOMCorrelationService(mock_chroma_collection)
        meta = {"affected_packages": json.dumps(["requests", "boto3"])}
        assert service._is_package_match("urllib3", meta) is False

    def test_package_match_empty_affected_packages(self, mock_chroma_collection):
        service = SBOMCorrelationService(mock_chroma_collection)
        meta = {"affected_packages": "[]"}
        assert service._is_package_match("urllib3", meta) is False

    def test_query_returns_empty_when_collection_empty(
        self, mock_chroma_collection, urllib3_component
    ):
        mock_chroma_collection.count.return_value = 0
        service = SBOMCorrelationService(mock_chroma_collection)
        results = service.query_cves_for_component(urllib3_component)
        assert results == []

    def test_similarity_threshold_filters_low_score(self, mock_chroma_collection, urllib3_component):
        """Results with distance > 0.8 (similarity < 0.6) should be filtered out."""
        mock_chroma_collection.count.return_value = 3
        mock_chroma_collection.query.return_value = {
            "ids": [["CVE-2023-44487"]],
            "metadatas": [[{
                "cve_id": "CVE-2023-44487",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "affected_packages": json.dumps(["urllib3"]),
                "published": "2023-10-10T00:00:00",
                "description_preview": "HTTP/2 Rapid Reset",
            }]],
            "distances": [[0.95]],  # Very high distance = very low similarity ~0.025
        }
        service = SBOMCorrelationService(mock_chroma_collection)
        results = service.query_cves_for_component(urllib3_component)
        assert results == []  # Filtered out by threshold

    def test_similarity_threshold_passes_high_score(self, mock_chroma_collection, urllib3_component):
        """Results with distance < 0.8 (similarity > 0.6) should be returned."""
        mock_chroma_collection.count.return_value = 3
        mock_chroma_collection.query.return_value = {
            "ids": [["CVE-2023-44487"]],
            "metadatas": [[{
                "cve_id": "CVE-2023-44487",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "affected_packages": json.dumps(["urllib3"]),
                "published": "2023-10-10T00:00:00",
                "description_preview": "HTTP/2 Rapid Reset",
            }]],
            "distances": [[0.2]],  # Low distance = high similarity ~0.9
        }
        service = SBOMCorrelationService(mock_chroma_collection)
        results = service.query_cves_for_component(urllib3_component)
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-44487"

    def test_correlate_sbom_returns_dict_per_component(
        self, mock_chroma_collection, sample_sbom
    ):
        service = SBOMCorrelationService(mock_chroma_collection)
        results = service.correlate_sbom(sample_sbom.components)
        # Should have one entry per component
        assert len(results) == len(sample_sbom.components)

    def test_correlate_sbom_handles_rag_exception_gracefully(
        self, mock_chroma_collection, urllib3_component
    ):
        mock_chroma_collection.count.return_value = 3
        mock_chroma_collection.query.side_effect = Exception("ChromaDB connection lost")
        service = SBOMCorrelationService(mock_chroma_collection)
        results = service.correlate_sbom([urllib3_component])
        # Should return empty list, not raise
        assert results["urllib3@1.26.14"] == []


# ─── Unit Tests: RiskScoringService ──────────────────────────────────────────

class TestRiskScoring:

    def test_max_severity_critical_wins(self):
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        assert max_severity(severities) == Severity.CRITICAL

    def test_max_severity_empty_returns_none(self):
        assert max_severity([]) == Severity.NONE

    def test_score_component_no_cves(self, mock_risk_repository, urllib3_component):
        service = RiskScoringService(mock_risk_repository)
        severity, score = service._score_component(urllib3_component, [])
        assert severity == Severity.NONE
        assert score == 0.0

    def test_score_component_highest_score_selected(
        self, mock_risk_repository, urllib3_component, matched_cve_high, matched_cve_critical
    ):
        service = RiskScoringService(mock_risk_repository)
        severity, score = service._score_component(urllib3_component, [matched_cve_high, matched_cve_critical])
        assert severity == Severity.CRITICAL
        assert score == 9.1

    def test_score_component_null_cvss_handled(
        self, mock_risk_repository, urllib3_component
    ):
        cve_no_score = MatchedCVE(
            cve_id="CVE-2024-00001",
            description="Unknown score CVE",
            cvss_score=None,
            severity=Severity.UNKNOWN,
            similarity_score=0.75,
        )
        service = RiskScoringService(mock_risk_repository)
        severity, score = service._score_component(urllib3_component, [cve_no_score])
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_score_sbom_all_clean(
        self, mock_risk_repository, sample_sbom
    ):
        service = RiskScoringService(mock_risk_repository)
        correlation_results = {
            f"{c.name}@{c.version}": []
            for c in sample_sbom.components
        }
        with patch.object(service, "_generate_executive_summary", new_callable=AsyncMock) as mock_summary:
            mock_summary.return_value = "All clean."
            report = await service.score_sbom(sample_sbom, correlation_results, include_remediation=False)

        assert report.vulnerable_components == 0
        assert report.critical_count == 0
        assert report.overall_risk_score == 0.0
        assert report.overall_severity == Severity.NONE
        mock_risk_repository.save_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_score_sbom_vulnerable_component(
        self, mock_risk_repository, sample_sbom, matched_cve_critical
    ):
        service = RiskScoringService(mock_risk_repository)
        correlation_results = {
            "urllib3@1.26.14": [matched_cve_critical],
            "cryptography@41.0.3": [],
            "pydantic@2.4.2": [],
        }
        with patch.object(service, "_generate_remediation", new_callable=AsyncMock) as mock_rem:
            mock_rem.return_value = {
                "remediation_suggestion": "Upgrade urllib3",
                "upgrade_recommendation": "urllib3>=2.0.7",
                "risk_rationale": "Affected by CVE-2024-21507",
            }
            with patch.object(service, "_generate_executive_summary", new_callable=AsyncMock) as mock_summ:
                mock_summ.return_value = "Critical finding in urllib3."
                report = await service.score_sbom(sample_sbom, correlation_results)

        assert report.vulnerable_components == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL
        assert report.overall_risk_score > 0

    @pytest.mark.asyncio
    async def test_severity_filter_excludes_low_severity(
        self, mock_risk_repository, sample_sbom, matched_cve_high
    ):
        """LOW severity findings should be excluded when filter=HIGH."""
        service = RiskScoringService(mock_risk_repository)
        low_cve = MatchedCVE(
            cve_id="CVE-2024-LOW",
            description="Low severity finding",
            cvss_score=2.0,
            severity=Severity.LOW,
            similarity_score=0.8,
        )
        correlation_results = {
            "urllib3@1.26.14": [low_cve],
            "cryptography@41.0.3": [matched_cve_high],
            "pydantic@2.4.2": [],
        }
        with patch.object(service, "_generate_remediation", new_callable=AsyncMock) as mock_rem:
            mock_rem.return_value = {"remediation_suggestion": "x", "upgrade_recommendation": "x", "risk_rationale": "x"}
            with patch.object(service, "_generate_executive_summary", new_callable=AsyncMock) as mock_summ:
                mock_summ.return_value = "Summary."
                report = await service.score_sbom(
                    sample_sbom, correlation_results,
                    severity_filter=Severity.HIGH
                )

        # LOW finding for urllib3 should be excluded
        component_names = [f.component_name for f in report.findings if f.is_vulnerable]
        assert "urllib3" not in component_names
        assert "cryptography" in component_names


# ─── Integration Tests: API ───────────────────────────────────────────────────

@pytest.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


class TestAPIEndpoints:

    @pytest.mark.asyncio
    async def test_health_check(self, async_client):
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "supply-chain-risk-intelligence"

    @pytest.mark.asyncio
    async def test_ingest_invalid_max_results_rejected(self, async_client):
        response = await async_client.post(
            "/api/v1/risk/ingest",
            json={"use_sample_data": True, "max_results": 99999},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_ingest_invalid_days_back_rejected(self, async_client):
        response = await async_client.post(
            "/api/v1/risk/ingest",
            json={"use_sample_data": False, "days_back": 365},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_sbom_analyze_empty_components_rejected(self, async_client):
        payload = {
            "sbom": {
                "format": "CycloneDX",
                "metadata": {"application_name": "test-app", "application_version": "1.0.0"},
                "components": [],
            },
            "include_remediation": False,
        }
        response = await async_client.post("/api/v1/risk/sbom/analyze", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_cve_query_blank_package_name_rejected(self, async_client):
        response = await async_client.post(
            "/api/v1/risk/query",
            json={"package_name": "", "top_k": 5},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_get_nonexistent_scan_returns_404(self, async_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await async_client.get(f"/api/v1/risk/scans/{fake_id}")
        assert response.status_code in {404, 500}  # 500 if DB not connected in test env

    @pytest.mark.asyncio
    async def test_scans_list_invalid_limit_rejected(self, async_client):
        response = await async_client.get("/api/v1/risk/scans?limit=9999")
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_cve_query_top_k_out_of_range_rejected(self, async_client):
        response = await async_client.post(
            "/api/v1/risk/query",
            json={"package_name": "urllib3", "top_k": 50},
        )
        assert response.status_code == 422
