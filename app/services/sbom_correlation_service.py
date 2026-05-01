"""
SBOM Correlation Service — Supply Chain Risk Intelligence (POC-04)

For each component in the SBOM:
  1. Build a semantic query string (package name + version + ecosystem)
  2. Query ChromaDB (RAG) for semantically similar CVE descriptions
  3. Filter by similarity threshold and package name match
  4. Return matched CVEs per component with confidence scores

Design decisions:
  - RAG retrieval is fuzzy (semantic) — allows catching CVEs even when
    package names differ slightly (e.g. "pillow" vs "Pillow" vs "PIL")
  - Post-retrieval filtering applies exact package name matching as a
    second gate to reduce false positives
  - If ChromaDB collection is empty, returns a warning and skips correlation
"""
import json
import time
from typing import List, Dict, Any, Optional, Tuple

from loguru import logger

from app.core.config import settings
from app.core.exceptions import RAGException
from app.schemas.risk import (
    SBOMComponent, MatchedCVE, Severity, CVEQueryResponse
)


class SBOMCorrelationService:
    """
    Correlates SBOM components with CVEs using semantic RAG retrieval.
    Operates on the ChromaDB collection populated by NVDIngestionService.
    """

    def __init__(self, chroma_collection):
        self.collection = chroma_collection
        logger.info("SBOMCorrelationService initialized")

    def _build_query(self, component: SBOMComponent) -> str:
        """
        Build a rich semantic query for a SBOM component.
        The more context we include, the better the embedding match.
        """
        parts = [
            f"Python package {component.name} version {component.version}",
            f"vulnerability security issue CVE",
        ]
        if component.description:
            parts.append(component.description[:100])
        return " ".join(parts)

    def _is_package_match(self, component_name: str, cve_metadata: Dict[str, Any]) -> bool:
        """
        Post-retrieval gate: check if the CVE's affected_packages list
        contains the component name (case-insensitive, partial match).
        Prevents false positives from pure semantic similarity.
        """
        affected_raw = cve_metadata.get("affected_packages", "[]")
        try:
            affected = json.loads(affected_raw) if isinstance(affected_raw, str) else affected_raw
        except json.JSONDecodeError:
            affected = []

        name_lower = component_name.lower()
        for pkg in affected:
            pkg_lower = pkg.lower().split(":")[0]  # strip version part
            # Fuzzy match: either exact or one contains the other
            if name_lower == pkg_lower or name_lower in pkg_lower or pkg_lower in name_lower:
                return True
        return False

    def _parse_chroma_result(
        self, cve_id: str, metadata: Dict, distance: float, component: SBOMComponent
    ) -> Optional[MatchedCVE]:
        """Convert a ChromaDB result row into a MatchedCVE schema object."""
        try:
            # ChromaDB returns cosine distance (0=identical, 2=opposite)
            # Convert to similarity score 0.0–1.0
            similarity_score = max(0.0, 1.0 - (distance / 2.0))

            if similarity_score < settings.RAG_SIMILARITY_THRESHOLD:
                return None

            cvss_score_raw = metadata.get("cvss_score", "0")
            try:
                cvss_score = float(cvss_score_raw)
            except (ValueError, TypeError):
                cvss_score = 0.0

            severity_str = metadata.get("severity", "UNKNOWN")
            severity = Severity(severity_str) if severity_str in Severity.__members__ else Severity.UNKNOWN

            from datetime import datetime
            published_str = metadata.get("published", "")
            try:
                published = datetime.fromisoformat(published_str)
            except (ValueError, TypeError):
                published = None

            return MatchedCVE(
                cve_id=cve_id,
                description=metadata.get("description_preview", "No description"),
                cvss_score=cvss_score if cvss_score > 0 else None,
                severity=severity,
                similarity_score=round(similarity_score, 4),
                affected_versions=[],  # Populated by risk scoring service
                published=published,
                remediation_available=cvss_score > 0,
            )
        except Exception as e:
            logger.warning(f"Failed to parse ChromaDB result for {cve_id}: {e}")
            return None

    def query_cves_for_component(
        self, component: SBOMComponent, top_k: Optional[int] = None
    ) -> List[MatchedCVE]:
        """
        Query ChromaDB for CVEs matching this SBOM component.
        Returns matched CVEs sorted by similarity score descending.
        """
        k = top_k or settings.RAG_TOP_K
        query_text = self._build_query(component)

        try:
            collection_count = self.collection.count()
            if collection_count == 0:
                logger.warning("ChromaDB collection is empty — run NVD ingestion first")
                return []

            results = self.collection.query(
                query_texts=[query_text],
                n_results=min(k * 3, collection_count),  # Over-fetch, then filter
                include=["metadatas", "distances", "documents"],
            )

            ids = results.get("ids", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            matched: List[MatchedCVE] = []
            for cve_id, meta, dist in zip(ids, metadatas, distances):
                # Post-retrieval package name filter
                if not self._is_package_match(component.name, meta):
                    continue

                cve_match = self._parse_chroma_result(cve_id, meta, dist, component)
                if cve_match:
                    matched.append(cve_match)

            # Sort by severity then similarity
            severity_order = {
                Severity.CRITICAL: 0, Severity.HIGH: 1,
                Severity.MEDIUM: 2, Severity.LOW: 3,
                Severity.NONE: 4, Severity.UNKNOWN: 5,
            }
            matched.sort(key=lambda x: (severity_order.get(x.severity, 5), -x.similarity_score))

            return matched[:k]

        except Exception as e:
            logger.error(f"ChromaDB query failed for {component.name}: {e}")
            raise RAGException(str(e), "query")

    def correlate_sbom(
        self, components: List[SBOMComponent]
    ) -> Dict[str, List[MatchedCVE]]:
        """
        Run RAG correlation for all SBOM components.
        Returns dict mapping component name → list of matched CVEs.
        """
        start_time = time.time()
        results: Dict[str, List[MatchedCVE]] = {}
        total_matches = 0

        for component in components:
            try:
                matches = self.query_cves_for_component(component)
                component_key = f"{component.name}@{component.version}"
                results[component_key] = matches
                total_matches += len(matches)

                if matches:
                    highest = matches[0]
                    logger.info(
                        f"[SBOM] {component.name}@{component.version} → "
                        f"{len(matches)} CVEs | highest={highest.severity.value} "
                        f"({highest.cve_id})"
                    )
                else:
                    logger.debug(f"[SBOM] {component.name}@{component.version} → no CVEs matched")

            except RAGException as e:
                logger.error(f"RAG query failed for {component.name}: {e.detail}")
                results[f"{component.name}@{component.version}"] = []

        duration_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(
            f"SBOM correlation complete | components={len(components)} "
            f"total_matches={total_matches} duration_ms={duration_ms}"
        )
        return results

    def query_package(
        self, package_name: str, package_version: Optional[str] = None, top_k: int = 5
    ) -> CVEQueryResponse:
        """
        Direct CVE query for a single package — used by the /query endpoint.
        """
        start_time = time.time()
        component = SBOMComponent(
            name=package_name,
            version=package_version or "unknown",
        )
        matches = self.query_cves_for_component(component, top_k=top_k)
        query_str = f"{package_name}" + (f"=={package_version}" if package_version else "")

        return CVEQueryResponse(
            query=query_str,
            results=matches,
            total_found=len(matches),
            query_time_ms=round((time.time() - start_time) * 1000, 2),
        )
