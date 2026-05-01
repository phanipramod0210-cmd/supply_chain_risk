"""
Risk Scoring Service — Supply Chain Risk Intelligence (POC-04)

For each SBOM component with matched CVEs:
  1. Compute highest CVSS score and severity
  2. Generate LLM-powered remediation suggestion (upgrade version, patch, mitigate)
  3. Aggregate to produce overall SBOM risk score and executive summary
  4. Bucket findings into CRITICAL / HIGH / MEDIUM / LOW / CLEAN categories

LLM is used ONLY for remediation text — scoring is deterministic CVSS math.
"""
import json
import time
import uuid
import asyncio
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any

import anthropic
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings
from app.core.exceptions import RiskScoringException
from app.schemas.risk import (
    SBOMComponent, SBOMManifest, MatchedCVE, ComponentRiskFinding,
    SBOMRiskReport, Severity
)


SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.NONE: 1, Severity.UNKNOWN: 0,
}


def max_severity(severities: List[Severity]) -> Severity:
    if not severities:
        return Severity.NONE
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


class RiskScoringService:
    """
    Computes risk scores from CVE matches and generates LLM remediation advice.
    """

    def __init__(self, risk_repository):
        self.repository = risk_repository
        self.llm_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        logger.info("RiskScoringService initialized")

    def _score_component(
        self, component: SBOMComponent, matched_cves: List[MatchedCVE]
    ) -> Tuple[Severity, float]:
        """
        Compute the highest severity and CVSS score for a component's CVE matches.
        Returns (highest_severity, highest_cvss_score).
        """
        if not matched_cves:
            return Severity.NONE, 0.0

        scores = [c.cvss_score for c in matched_cves if c.cvss_score is not None]
        severities = [c.severity for c in matched_cves]

        highest_score = max(scores) if scores else 0.0
        highest_severity = max_severity(severities)
        return highest_severity, highest_score

    def _build_remediation_prompt(
        self, component: SBOMComponent, matched_cves: List[MatchedCVE]
    ) -> str:
        cve_summary = "\n".join([
            f"- {c.cve_id} (CVSS {c.cvss_score or 'N/A'}, {c.severity.value}): {c.description[:200]}"
            for c in matched_cves[:5]
        ])

        return f"""You are a supply chain security engineer generating actionable remediation advice.

Component: {component.name} version {component.version}
Package Manager: PyPI (Python)
PURL: {component.purl or 'N/A'}

Matched CVEs:
{cve_summary}

Generate a concise, actionable remediation response in JSON with these exact fields:
{{
  "remediation_suggestion": "Specific step-by-step guidance to remediate these vulnerabilities (2-3 sentences max)",
  "upgrade_recommendation": "Recommended safe version to upgrade to, e.g. 'Upgrade to {component.name}>=2.0.7'",
  "risk_rationale": "Brief technical explanation of why these CVEs pose risk to this component (1-2 sentences)"
}}

Rules:
- Be specific to the package name and version provided
- If multiple CVEs share a single fix (e.g. upgrade), consolidate the advice
- If no safe version is known, suggest isolating the component or disabling affected features
- Keep remediation_suggestion under 100 words
- Response must be valid JSON only, no markdown"""

    @retry(
        stop=stop_after_attempt(settings.LLM_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((anthropic.APIConnectionError, anthropic.RateLimitError)),
    )
    async def _generate_remediation(
        self, component: SBOMComponent, matched_cves: List[MatchedCVE]
    ) -> Dict[str, str]:
        """Call LLM to generate remediation advice. Falls back to template if LLM fails."""
        try:
            prompt = self._build_remediation_prompt(component, matched_cves)
            response = await asyncio.wait_for(
                self.llm_client.messages.create(
                    model=settings.LLM_MODEL,
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a security engineer. Respond with valid JSON only.",
                ),
                timeout=settings.LLM_TIMEOUT_SECONDS,
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw.strip())

        except asyncio.TimeoutError:
            logger.warning(f"LLM remediation timeout for {component.name} — using template")
        except (json.JSONDecodeError, anthropic.APIError, Exception) as e:
            logger.warning(f"LLM remediation failed for {component.name}: {e} — using template")

        # Fallback template
        highest = matched_cves[0] if matched_cves else None
        return {
            "remediation_suggestion": (
                f"Upgrade {component.name} from {component.version} to the latest stable version. "
                f"Review NIST NVD for {', '.join(c.cve_id for c in matched_cves[:3])} for patch availability. "
                "Apply vendor security patches immediately for CRITICAL/HIGH findings."
            ),
            "upgrade_recommendation": f"Upgrade {component.name} to latest stable release",
            "risk_rationale": (
                f"{component.name} {component.version} is affected by {len(matched_cves)} known CVE(s) "
                f"with highest severity {highest.severity.value if highest else 'UNKNOWN'}."
            ),
        }

    async def score_sbom(
        self,
        sbom: SBOMManifest,
        correlation_results: Dict[str, List[MatchedCVE]],
        include_remediation: bool = True,
        severity_filter: Optional[Severity] = None,
    ) -> SBOMRiskReport:
        """
        Full SBOM risk scoring pipeline.
        Generates per-component findings and aggregate report.
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())

        logger.info(f"Risk scoring started | scan_id={scan_id} components={len(sbom.components)}")

        findings: List[ComponentRiskFinding] = []
        critical_count = high_count = medium_count = low_count = 0
        max_scores: List[float] = []

        for component in sbom.components:
            key = f"{component.name}@{component.version}"
            matched_cves = correlation_results.get(key, [])

            highest_severity, highest_score = self._score_component(component, matched_cves)
            is_vulnerable = highest_severity not in {Severity.NONE, Severity.UNKNOWN} and len(matched_cves) > 0

            # Apply severity filter
            if severity_filter and is_vulnerable:
                if SEVERITY_ORDER.get(highest_severity, 0) < SEVERITY_ORDER.get(severity_filter, 0):
                    continue

            # Count severities
            if highest_severity == Severity.CRITICAL:
                critical_count += 1
            elif highest_severity == Severity.HIGH:
                high_count += 1
            elif highest_severity == Severity.MEDIUM:
                medium_count += 1
            elif highest_severity == Severity.LOW:
                low_count += 1

            if highest_score > 0:
                max_scores.append(highest_score)

            # Generate remediation (only for vulnerable components)
            remediation: Dict[str, str] = {}
            if include_remediation and is_vulnerable and matched_cves:
                remediation = await self._generate_remediation(component, matched_cves)

            finding = ComponentRiskFinding(
                component_name=component.name,
                component_version=component.version,
                purl=component.purl,
                matched_cves=matched_cves,
                highest_severity=highest_severity,
                highest_cvss_score=highest_score,
                is_vulnerable=is_vulnerable,
                remediation_suggestion=remediation.get("remediation_suggestion"),
                upgrade_recommendation=remediation.get("upgrade_recommendation"),
                risk_rationale=remediation.get("risk_rationale", "No CVE matches found."),
            )
            findings.append(finding)

        # Aggregate risk score — weighted average of top CVSS scores
        if max_scores:
            max_scores.sort(reverse=True)
            # Weight: top score × 0.5 + average of rest × 0.5
            overall_risk_score = round(
                max_scores[0] * 0.5 + (sum(max_scores[1:]) / max(len(max_scores[1:]), 1)) * 0.5, 2
            )
        else:
            overall_risk_score = 0.0

        overall_severity = (
            Severity.CRITICAL if critical_count > 0 else
            Severity.HIGH if high_count > 0 else
            Severity.MEDIUM if medium_count > 0 else
            Severity.LOW if low_count > 0 else
            Severity.NONE
        )

        vulnerable_components = sum(1 for f in findings if f.is_vulnerable)
        clean_components = len(findings) - vulnerable_components

        executive_summary = await self._generate_executive_summary(
            sbom=sbom,
            findings=findings,
            critical_count=critical_count,
            high_count=high_count,
            overall_severity=overall_severity,
            overall_risk_score=overall_risk_score,
        )

        scan_duration_ms = round((time.time() - start_time) * 1000, 2)

        report = SBOMRiskReport(
            scan_id=scan_id,
            application_name=sbom.metadata.application_name,
            application_version=sbom.metadata.application_version,
            total_components=len(sbom.components),
            vulnerable_components=vulnerable_components,
            clean_components=clean_components,
            findings=findings,
            summary_stats={
                "remediation_included": include_remediation,
                "severity_filter_applied": severity_filter.value if severity_filter else None,
                "sbom_format": sbom.format.value,
            },
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            overall_risk_score=overall_risk_score,
            overall_severity=overall_severity,
            executive_summary=executive_summary,
            scan_duration_ms=scan_duration_ms,
            generated_at=datetime.utcnow(),
        )

        await self.repository.save_scan(report)
        logger.info(
            f"Risk scoring complete | scan_id={scan_id} "
            f"vulnerable={vulnerable_components}/{len(sbom.components)} "
            f"critical={critical_count} high={high_count} "
            f"overall_score={overall_risk_score} ms={scan_duration_ms}"
        )
        return report

    async def _generate_executive_summary(
        self,
        sbom: SBOMManifest,
        findings: List[ComponentRiskFinding],
        critical_count: int,
        high_count: int,
        overall_severity: Severity,
        overall_risk_score: float,
    ) -> str:
        """Generate a 2-3 sentence CISO-grade executive summary using LLM."""
        vulnerable = [f for f in findings if f.is_vulnerable]
        if not vulnerable:
            return (
                f"{sbom.metadata.application_name} v{sbom.metadata.application_version} "
                f"has {len(sbom.components)} dependencies with no known CVE matches identified. "
                "Supply chain risk posture is currently CLEAN."
            )

        top_cves = []
        for f in vulnerable[:3]:
            if f.matched_cves:
                top_cves.append(f"{f.matched_cves[0].cve_id} in {f.component_name}")

        try:
            prompt = f"""Write a 2-3 sentence executive summary for a CISO about this software supply chain risk report.

Application: {sbom.metadata.application_name} v{sbom.metadata.application_version}
Total dependencies scanned: {len(sbom.components)}
Vulnerable dependencies: {len(vulnerable)}
Critical findings: {critical_count}
High findings: {high_count}
Overall risk score: {overall_risk_score}/10
Overall severity: {overall_severity.value}
Notable CVEs: {', '.join(top_cves) if top_cves else 'Multiple'}

Write for a non-technical executive. Be direct. State the risk level, impact, and top priority action.
Return plain text only — no JSON, no markdown."""

            response = await asyncio.wait_for(
                self.llm_client.messages.create(
                    model=settings.LLM_MODEL,
                    max_tokens=200,
                    messages=[{"role": "user", "content": prompt}],
                ),
                timeout=20,
            )
            return response.content[0].text.strip()

        except Exception as e:
            logger.warning(f"Executive summary LLM failed: {e} — using template")
            return (
                f"{sbom.metadata.application_name} v{sbom.metadata.application_version} "
                f"has {len(vulnerable)} vulnerable dependencies out of {len(sbom.components)} total. "
                f"Overall risk score: {overall_risk_score}/10 ({overall_severity.value}). "
                f"Immediate action required for {critical_count} CRITICAL and {high_count} HIGH severity findings."
            )
