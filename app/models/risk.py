"""
SQLAlchemy ORM Models for Supply Chain Risk Intelligence.

Tables:
  - cve_records      : Normalized CVE data from NVD (avoids re-fetching)
  - sbom_scans       : Each SBOM submission = one scan record
  - risk_findings    : One row per vulnerable component per scan
  - ingestion_logs   : NVD ingestion audit trail
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Boolean, Integer,
    DateTime, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship

from app.core.database import Base


class CVERecord(Base):
    """
    Cached CVE record from NVD.
    Stored to avoid re-fetching and to serve as ground truth for audit.
    """
    __tablename__ = "cve_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(30), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=False)
    published = Column(DateTime, nullable=False, index=True)
    last_modified = Column(DateTime, nullable=False)

    # CVSS metrics
    cvss_version = Column(String(10))
    cvss_base_score = Column(Float)
    cvss_base_severity = Column(String(20), index=True)
    cvss_vector_string = Column(String(200))
    attack_vector = Column(String(20))
    attack_complexity = Column(String(10))
    privileges_required = Column(String(10))
    confidentiality_impact = Column(String(10))
    integrity_impact = Column(String(10))
    availability_impact = Column(String(10))

    # Metadata
    affected_packages = Column(JSONB, default=list)
    cwe_ids = Column(JSONB, default=list)
    references = Column(JSONB, default=list)
    embedded_in_chroma = Column(Boolean, default=False)
    ingested_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_cve_severity_published", "cvss_base_severity", "published"),
    )


class SBOMScan(Base):
    """Records each SBOM analysis submission."""
    __tablename__ = "sbom_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(36), nullable=False, unique=True, index=True)
    application_name = Column(String(200), nullable=False, index=True)
    application_version = Column(String(100), nullable=False)
    supplier = Column(String(200))
    sbom_format = Column(String(20), default="CycloneDX")

    # Summary counts
    total_components = Column(Integer, nullable=False)
    vulnerable_components = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    overall_risk_score = Column(Float, default=0.0)
    overall_severity = Column(String(20), default="NONE")

    executive_summary = Column(Text)
    scan_duration_ms = Column(Float)
    status = Column(String(20), default="COMPLETED", index=True)
    scanned_at = Column(DateTime, default=datetime.utcnow, index=True)

    findings = relationship("RiskFinding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_sbom_scan_app_date", "application_name", "scanned_at"),
    )


class RiskFinding(Base):
    """One row per vulnerable component detected in a SBOM scan."""
    __tablename__ = "risk_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("sbom_scans.id"), nullable=False)
    component_name = Column(String(200), nullable=False, index=True)
    component_version = Column(String(100), nullable=False)
    purl = Column(String(500))

    # Matched CVEs stored as JSONB array
    matched_cves = Column(JSONB, default=list)
    highest_severity = Column(String(20), nullable=False, index=True)
    highest_cvss_score = Column(Float, default=0.0)
    is_vulnerable = Column(Boolean, default=False, index=True)

    remediation_suggestion = Column(Text)
    upgrade_recommendation = Column(String(500))
    risk_rationale = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("SBOMScan", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_severity_component", "highest_severity", "component_name"),
    )


class IngestionLog(Base):
    """Audit log for every NVD ingestion run."""
    __tablename__ = "ingestion_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ingestion_id = Column(String(36), nullable=False, unique=True, index=True)
    source = Column(String(50), nullable=False)  # "nvd_api" | "sample_data"
    total_fetched = Column(Integer, default=0)
    total_embedded = Column(Integer, default=0)
    total_skipped = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    duration_ms = Column(Float)
    status = Column(String(20), default="COMPLETED")
    error_detail = Column(Text)
    ingested_at = Column(DateTime, default=datetime.utcnow, index=True)
