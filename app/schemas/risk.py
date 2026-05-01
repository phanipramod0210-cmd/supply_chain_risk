"""
Pydantic v2 schemas for Supply Chain Risk Intelligence.
Covers: SBOM manifest, CVE records, risk findings, and API responses.
"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class SBOMFormat(str, Enum):
    CYCLONEDX = "CycloneDX"
    SPDX = "SPDX"
    GENERIC = "GENERIC"


# ─── SBOM Schemas ─────────────────────────────────────────────────────────────

class SBOMComponent(BaseModel):
    """A single dependency in the SBOM manifest."""
    name: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., min_length=1, max_length=100)
    purl: Optional[str] = Field(None, max_length=500)
    component_type: str = Field("library", max_length=50)
    license_id: Optional[str] = Field(None, max_length=100)
    supplier: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=500)

    @field_validator("version")
    @classmethod
    def clean_version(cls, v: str) -> str:
        return v.strip().lstrip("v=")

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Component name cannot be blank")
        return v.strip().lower()


class SBOMMetadata(BaseModel):
    application_name: str = Field(..., min_length=1, max_length=200)
    application_version: str = Field(..., min_length=1, max_length=100)
    supplier: Optional[str] = Field(None, max_length=200)
    generated_at: Optional[datetime] = None


class SBOMManifest(BaseModel):
    """Full SBOM submission for risk analysis."""
    format: SBOMFormat = SBOMFormat.CYCLONEDX
    metadata: SBOMMetadata
    components: List[SBOMComponent] = Field(..., min_length=1)
    scan_id: Optional[str] = Field(None, max_length=100)

    @model_validator(mode="after")
    def validate_component_count(self) -> "SBOMManifest":
        from app.core.config import settings
        if len(self.components) > settings.MAX_SBOM_COMPONENTS:
            raise ValueError(
                f"SBOM has {len(self.components)} components, "
                f"exceeding maximum of {settings.MAX_SBOM_COMPONENTS}"
            )
        return self


class SBOMAnalysisRequest(BaseModel):
    """API request to analyze a SBOM manifest."""
    sbom: SBOMManifest
    include_remediation: bool = True
    severity_filter: Optional[Severity] = None  # Only return findings at or above this severity
    use_sample_data: bool = False  # Use bundled sample SBOM for demo purposes


# ─── CVE / NVD Schemas ────────────────────────────────────────────────────────

class CVSSMetrics(BaseModel):
    version: str = "3.1"
    base_score: float = Field(..., ge=0.0, le=10.0)
    base_severity: Severity
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    vector_string: Optional[str] = None


class CVERecord(BaseModel):
    """Parsed CVE record from NVD."""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    published: datetime
    last_modified: datetime
    cvss: Optional[CVSSMetrics] = None
    severity: Severity = Severity.UNKNOWN
    affected_packages: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def uppercase_cve_id(cls, v: str) -> str:
        return v.upper().strip()


class NVDIngestRequest(BaseModel):
    """Request to ingest CVEs from NVD API or local feed."""
    use_sample_data: bool = False
    keyword_filter: Optional[str] = Field(None, max_length=100)
    days_back: int = Field(30, ge=1, le=120)
    max_results: int = Field(100, ge=1, le=2000)


class NVDIngestResponse(BaseModel):
    ingestion_id: str
    total_fetched: int
    total_embedded: int
    total_skipped_duplicates: int
    failed_count: int
    duration_ms: float
    collection_total: int
    timestamp: datetime


# ─── Risk Finding Schemas ─────────────────────────────────────────────────────

class MatchedCVE(BaseModel):
    """A CVE that matched a SBOM component."""
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: Severity
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    affected_versions: List[str] = Field(default_factory=list)
    published: Optional[datetime] = None
    remediation_available: bool = False


class ComponentRiskFinding(BaseModel):
    """Risk assessment for a single SBOM component."""
    component_name: str
    component_version: str
    purl: Optional[str] = None
    matched_cves: List[MatchedCVE]
    highest_severity: Severity
    highest_cvss_score: float = 0.0
    is_vulnerable: bool
    remediation_suggestion: Optional[str] = None
    upgrade_recommendation: Optional[str] = None
    risk_rationale: str


class SBOMRiskReport(BaseModel):
    """Complete risk report for a full SBOM manifest."""
    scan_id: str
    application_name: str
    application_version: str
    total_components: int
    vulnerable_components: int
    clean_components: int
    findings: List[ComponentRiskFinding]
    summary_stats: Dict[str, Any]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_score: float = Field(..., ge=0.0, le=10.0)
    overall_severity: Severity
    executive_summary: str
    scan_duration_ms: float
    generated_at: datetime


# ─── RAG Query Schema ─────────────────────────────────────────────────────────

class CVEQueryRequest(BaseModel):
    """Query the CVE vector store directly for a specific package."""
    package_name: str = Field(..., min_length=1, max_length=200)
    package_version: Optional[str] = Field(None, max_length=100)
    top_k: int = Field(5, ge=1, le=20)

    @field_validator("package_name")
    @classmethod
    def clean_package_name(cls, v: str) -> str:
        return v.strip().lower()


class CVEQueryResponse(BaseModel):
    query: str
    results: List[MatchedCVE]
    total_found: int
    query_time_ms: float
