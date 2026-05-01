"""
Risk Repository — Supply Chain Risk Intelligence (POC-04)
All PostgreSQL operations isolated in this layer.
"""
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from loguru import logger

from app.models.risk import CVERecord as CVERecordModel, SBOMScan, RiskFinding, IngestionLog
from app.schemas.risk import CVERecord, SBOMRiskReport, Severity
from app.core.exceptions import RepositoryException


class RiskRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    # ─── CVE Records ──────────────────────────────────────────────────────────

    async def upsert_cve_records(self, cves: List[CVERecord]) -> int:
        """
        Upsert CVE records to PostgreSQL.
        Uses ON CONFLICT DO UPDATE to handle re-ingestion gracefully.
        """
        try:
            upserted = 0
            for cve in cves:
                existing = await self.session.execute(
                    select(CVERecordModel).where(CVERecordModel.cve_id == cve.cve_id)
                )
                record = existing.scalar_one_or_none()

                if record:
                    # Update only if more recently modified
                    if cve.last_modified > record.last_modified:
                        record.last_modified = cve.last_modified
                        record.cvss_base_score = cve.cvss.base_score if cve.cvss else None
                        record.cvss_base_severity = cve.severity.value
                        record.embedded_in_chroma = True
                else:
                    record = CVERecordModel(
                        cve_id=cve.cve_id,
                        description=cve.description,
                        published=cve.published,
                        last_modified=cve.last_modified,
                        cvss_version=cve.cvss.version if cve.cvss else None,
                        cvss_base_score=cve.cvss.base_score if cve.cvss else None,
                        cvss_base_severity=cve.severity.value,
                        cvss_vector_string=cve.cvss.vector_string if cve.cvss else None,
                        attack_vector=cve.cvss.attack_vector if cve.cvss else None,
                        attack_complexity=cve.cvss.attack_complexity if cve.cvss else None,
                        privileges_required=cve.cvss.privileges_required if cve.cvss else None,
                        confidentiality_impact=cve.cvss.confidentiality_impact if cve.cvss else None,
                        integrity_impact=cve.cvss.integrity_impact if cve.cvss else None,
                        availability_impact=cve.cvss.availability_impact if cve.cvss else None,
                        affected_packages=cve.affected_packages,
                        cwe_ids=cve.cwe_ids,
                        references=cve.references,
                        embedded_in_chroma=True,
                    )
                    self.session.add(record)
                    upserted += 1

            await self.session.commit()
            logger.debug(f"CVE records upserted: {upserted} new, {len(cves) - upserted} updated")
            return upserted
        except Exception as e:
            await self.session.rollback()
            raise RepositoryException(str(e), "upsert_cve_records")

    # ─── SBOM Scan Persistence ────────────────────────────────────────────────

    async def save_scan(self, report: SBOMRiskReport) -> str:
        """Persist a complete SBOM scan report including all component findings."""
        try:
            scan = SBOMScan(
                scan_id=report.scan_id,
                application_name=report.application_name,
                application_version=report.application_version,
                total_components=report.total_components,
                vulnerable_components=report.vulnerable_components,
                critical_count=report.critical_count,
                high_count=report.high_count,
                medium_count=report.medium_count,
                low_count=report.low_count,
                overall_risk_score=report.overall_risk_score,
                overall_severity=report.overall_severity.value,
                executive_summary=report.executive_summary,
                scan_duration_ms=report.scan_duration_ms,
                status="COMPLETED",
            )
            self.session.add(scan)
            await self.session.flush()

            for finding in report.findings:
                if not finding.is_vulnerable:
                    continue  # Only persist vulnerable findings
                self.session.add(RiskFinding(
                    scan_id=scan.id,
                    component_name=finding.component_name,
                    component_version=finding.component_version,
                    purl=finding.purl,
                    matched_cves=[
                        {
                            "cve_id": c.cve_id,
                            "severity": c.severity.value,
                            "cvss_score": c.cvss_score,
                            "similarity_score": c.similarity_score,
                        }
                        for c in finding.matched_cves
                    ],
                    highest_severity=finding.highest_severity.value,
                    highest_cvss_score=finding.highest_cvss_score,
                    is_vulnerable=finding.is_vulnerable,
                    remediation_suggestion=finding.remediation_suggestion,
                    upgrade_recommendation=finding.upgrade_recommendation,
                    risk_rationale=finding.risk_rationale,
                ))

            await self.session.commit()
            logger.info(f"Scan persisted | scan_id={report.scan_id}")
            return report.scan_id
        except Exception as e:
            await self.session.rollback()
            raise RepositoryException(str(e), "save_scan")

    async def get_scan_by_id(self, scan_id: str) -> Optional[SBOMScan]:
        try:
            result = await self.session.execute(
                select(SBOMScan).where(SBOMScan.scan_id == scan_id)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            raise RepositoryException(str(e), "get_scan_by_id")

    async def get_scan_history(
        self, application_name: Optional[str] = None, limit: int = 20
    ) -> List[SBOMScan]:
        try:
            q = select(SBOMScan).order_by(desc(SBOMScan.scanned_at)).limit(min(limit, 100))
            if application_name:
                q = q.where(SBOMScan.application_name.ilike(f"%{application_name}%"))
            result = await self.session.execute(q)
            return result.scalars().all()
        except Exception as e:
            raise RepositoryException(str(e), "get_scan_history")

    # ─── Ingestion Logs ───────────────────────────────────────────────────────

    async def save_ingestion_log(self, **kwargs) -> str:
        try:
            log = IngestionLog(**kwargs)
            self.session.add(log)
            await self.session.commit()
            return kwargs.get("ingestion_id", "")
        except Exception as e:
            await self.session.rollback()
            raise RepositoryException(str(e), "save_ingestion_log")

    # ─── Dashboard / Analytics ────────────────────────────────────────────────

    async def get_risk_dashboard(self) -> Dict[str, Any]:
        """Aggregate risk metrics across all SBOM scans for the dashboard."""
        try:
            result = await self.session.execute(
                select(
                    func.count(SBOMScan.id).label("total_scans"),
                    func.sum(SBOMScan.vulnerable_components).label("total_vulnerable"),
                    func.sum(SBOMScan.critical_count).label("total_critical"),
                    func.sum(SBOMScan.high_count).label("total_high"),
                    func.avg(SBOMScan.overall_risk_score).label("avg_risk_score"),
                    func.sum(SBOMScan.total_components).label("total_components_scanned"),
                )
            )
            row = result.one()

            # Most frequently vulnerable packages
            vuln_result = await self.session.execute(
                select(
                    RiskFinding.component_name,
                    func.count(RiskFinding.id).label("occurrence_count"),
                    func.max(RiskFinding.highest_cvss_score).label("max_cvss"),
                )
                .where(RiskFinding.is_vulnerable == True)
                .group_by(RiskFinding.component_name)
                .order_by(desc("occurrence_count"))
                .limit(10)
            )
            top_vulnerable = [
                {"package": r.component_name, "occurrence_count": r.occurrence_count, "max_cvss": r.max_cvss}
                for r in vuln_result.all()
            ]

            return {
                "total_scans": row.total_scans or 0,
                "total_components_scanned": int(row.total_components_scanned or 0),
                "total_vulnerable_components": int(row.total_vulnerable or 0),
                "total_critical_findings": int(row.total_critical or 0),
                "total_high_findings": int(row.total_high or 0),
                "avg_risk_score": round(float(row.avg_risk_score or 0), 2),
                "top_vulnerable_packages": top_vulnerable,
            }
        except Exception as e:
            raise RepositoryException(str(e), "get_risk_dashboard")

    async def get_cve_stats(self) -> Dict[str, Any]:
        """Stats on ingested CVE records."""
        try:
            result = await self.session.execute(
                select(
                    func.count(CVERecordModel.id).label("total_cves"),
                    func.count(CVERecordModel.id).filter(CVERecordModel.cvss_base_severity == "CRITICAL").label("critical"),
                    func.count(CVERecordModel.id).filter(CVERecordModel.cvss_base_severity == "HIGH").label("high"),
                    func.count(CVERecordModel.id).filter(CVERecordModel.embedded_in_chroma == True).label("embedded"),
                )
            )
            row = result.one()
            return {
                "total_cves_ingested": row.total_cves or 0,
                "critical_cves": row.critical or 0,
                "high_cves": row.high or 0,
                "embedded_in_vector_store": row.embedded or 0,
            }
        except Exception as e:
            raise RepositoryException(str(e), "get_cve_stats")
