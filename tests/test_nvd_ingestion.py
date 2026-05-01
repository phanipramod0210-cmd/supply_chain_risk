"""
Test Suite — NVD Ingestion Service (POC-04)

Covers:
  - CVE parsing from raw NVD JSON (valid, missing CVSS, malformed)
  - Severity score mapping (CVSS thresholds)
  - Embedding document construction
  - Sample data loading
  - Deduplication logic
  - Ingestion response structure
"""
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

from app.services.nvd_ingestion_service import NVDParser, NVDIngestionService, score_to_severity
from app.schemas.risk import Severity, CVERecord
from app.core.exceptions import NVDFetchException, NVDParseException


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def parser():
    return NVDParser()


@pytest.fixture
def raw_cve_critical():
    return {
        "cve": {
            "id": "CVE-2023-44487",
            "published": "2023-10-10T14:15:10.883",
            "lastModified": "2024-01-12T18:15:49.740",
            "descriptions": [{"lang": "en", "value": "HTTP/2 Rapid Reset Attack causing denial of service."}],
            "metrics": {
                "cvssMetricV31": [{
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "confidentialityImpact": "NONE",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    }
                }]
            },
            "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-400"}]}],
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:a:python:urllib3:1.26.14:*:*:*:*:*:*:*", "matchCriteriaId": "X1"}
                    ]
                }]
            }],
            "references": [{"url": "https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f", "source": "cve@mitre.org"}],
        }
    }


@pytest.fixture
def raw_cve_no_cvss():
    return {
        "cve": {
            "id": "CVE-2024-99999",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "A newly discovered vulnerability with no CVSS score yet."}],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "references": [],
        }
    }


@pytest.fixture
def mock_chroma_collection():
    col = MagicMock()
    col.count.return_value = 0
    col.get.return_value = {"metadatas": []}
    col.query.return_value = {"ids": [[]], "metadatas": [[]], "distances": [[]]}
    col.upsert.return_value = None
    return col


@pytest.fixture
def mock_repository():
    repo = AsyncMock()
    repo.save_ingestion_log = AsyncMock(return_value="test-ingestion-id")
    repo.upsert_cve_records = AsyncMock(return_value=5)
    return repo


# ─── Unit Tests: NVDParser ────────────────────────────────────────────────────

class TestNVDParser:

    def test_parse_valid_cve(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        assert cve.cve_id == "CVE-2023-44487"
        assert "Rapid Reset" in cve.description
        assert cve.cvss is not None
        assert cve.cvss.base_score == 7.5
        assert cve.severity == Severity.HIGH
        assert cve.cvss.attack_vector == "NETWORK"

    def test_parse_cve_affected_packages_extracted(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        assert len(cve.affected_packages) >= 1
        assert any("urllib3" in pkg for pkg in cve.affected_packages)

    def test_parse_cve_cwe_extracted(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        assert "CWE-400" in cve.cwe_ids

    def test_parse_cve_references_extracted(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        assert len(cve.references) >= 1
        assert "github.com" in cve.references[0]

    def test_parse_cve_no_cvss_returns_unknown_severity(self, parser, raw_cve_no_cvss):
        cve = parser.parse_cve(raw_cve_no_cvss)
        assert cve.cve_id == "CVE-2024-99999"
        assert cve.cvss is None
        assert cve.severity == Severity.UNKNOWN

    def test_parse_cve_missing_english_description_fallback(self, parser):
        raw = {
            "cve": {
                "id": "CVE-2024-11111",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [{"lang": "es", "value": "Descripción en español."}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
            }
        }
        cve = parser.parse_cve(raw)
        assert cve.description == "No description available"

    def test_parse_cve_id_uppercase(self, parser, raw_cve_no_cvss):
        cve = parser.parse_cve(raw_cve_no_cvss)
        assert cve.cve_id == cve.cve_id.upper()

    def test_parse_cve_malformed_raises_nvd_parse_exception(self, parser):
        from app.core.exceptions import NVDParseException
        with pytest.raises(NVDParseException):
            parser.parse_cve({"cve": {}})  # Missing required 'id' field

    def test_build_embedding_document_contains_cve_id(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        doc = parser.build_embedding_document(cve)
        assert "CVE-2023-44487" in doc
        assert "HIGH" in doc
        assert "7.5" in doc

    def test_build_embedding_document_contains_affected_packages(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        doc = parser.build_embedding_document(cve)
        assert "urllib3" in doc

    def test_build_embedding_document_contains_description(self, parser, raw_cve_critical):
        cve = parser.parse_cve(raw_cve_critical)
        doc = parser.build_embedding_document(cve)
        assert "Rapid Reset" in doc


# ─── Unit Tests: Severity Mapping ────────────────────────────────────────────

class TestSeverityMapping:

    @pytest.mark.parametrize("score,expected", [
        (9.8, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.NONE),
        (None, Severity.UNKNOWN),
    ])
    def test_score_to_severity(self, score, expected):
        assert score_to_severity(score) == expected


# ─── Unit Tests: NVDIngestionService ─────────────────────────────────────────

class TestNVDIngestionService:

    @pytest.mark.asyncio
    async def test_ingest_sample_data_success(
        self, mock_repository, mock_chroma_collection
    ):
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        result = await service.ingest(use_sample_data=True)

        assert result.total_fetched > 0
        assert result.ingestion_id is not None
        assert result.duration_ms > 0
        mock_repository.save_ingestion_log.assert_called_once()
        mock_repository.upsert_cve_records.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_sample_data_embeds_to_chroma(
        self, mock_repository, mock_chroma_collection
    ):
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        await service.ingest(use_sample_data=True)
        mock_chroma_collection.upsert.assert_called()

    @pytest.mark.asyncio
    async def test_ingest_deduplicates_existing_cves(
        self, mock_repository, mock_chroma_collection, raw_cve_critical
    ):
        """CVEs already in ChromaDB should be skipped (not re-embedded)."""
        mock_chroma_collection.get.return_value = {
            "metadatas": [{"cve_id": "CVE-2023-44487"}]
        }
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        result = await service.ingest(use_sample_data=True)
        # CVE-2023-44487 is in the sample data — it should be skipped
        assert result.total_skipped_duplicates >= 1

    @pytest.mark.asyncio
    async def test_ingest_invalid_sample_path_raises(
        self, mock_repository, mock_chroma_collection
    ):
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        original = service.repository
        with patch("app.services.nvd_ingestion_service.settings") as mock_settings:
            mock_settings.SAMPLE_NVD_FEED_PATH = "/nonexistent/path.json"
            mock_settings.LLM_RETRY_ATTEMPTS = 3
            with pytest.raises(NVDFetchException):
                await service.ingest(use_sample_data=True)

    def test_embed_batch_skips_existing_ids(
        self, mock_repository, mock_chroma_collection
    ):
        """_embed_batch should skip CVEs already in the collection."""
        existing_ids = {"CVE-2023-44487"}
        mock_chroma_collection.get.return_value = {
            "metadatas": [{"cve_id": id} for id in existing_ids]
        }
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        parser = NVDParser()
        cve = CVERecord(
            cve_id="CVE-2023-44487",
            description="Already exists",
            published=datetime(2023, 1, 1),
            last_modified=datetime(2023, 1, 1),
            severity=Severity.HIGH,
        )
        embedded, failed = service._embed_batch([cve])
        assert embedded == 0
        mock_chroma_collection.upsert.assert_not_called()

    def test_embed_batch_new_cve_calls_upsert(
        self, mock_repository, mock_chroma_collection
    ):
        service = NVDIngestionService(mock_repository, mock_chroma_collection)
        cve = CVERecord(
            cve_id="CVE-2024-NEW001",
            description="A brand new CVE not yet in the store",
            published=datetime(2024, 1, 1),
            last_modified=datetime(2024, 1, 1),
            severity=Severity.CRITICAL,
        )
        embedded, failed = service._embed_batch([cve])
        assert embedded == 1
        mock_chroma_collection.upsert.assert_called_once()
