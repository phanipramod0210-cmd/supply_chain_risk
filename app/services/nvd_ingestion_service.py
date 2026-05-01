"""
NVD Ingestion Service — Supply Chain Risk Intelligence (POC-04)

Responsibilities:
  1. Fetch CVE data from NVD API (or load sample fixture for demo)
  2. Parse NVD JSON into normalized CVERecord schema
  3. Embed CVE descriptions into ChromaDB for semantic RAG retrieval
  4. Persist raw CVE records to PostgreSQL for audit/reporting
  5. Deduplicate — skip CVEs already embedded in the vector store

Architecture note:
  ChromaDB uses sentence-transformers (all-MiniLM-L6-v2) for embeddings
  unless ANTHROPIC_API_KEY is set, in which case we call the Anthropic
  embeddings API. For this POC we use ChromaDB's built-in embedding function
  (SentenceTransformerEmbeddingFunction) to avoid extra dependencies.
"""
import json
import time
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings
from app.core.exceptions import NVDFetchException, NVDParseException, RAGException
from app.schemas.risk import CVERecord, CVSSMetrics, Severity, NVDIngestResponse


# ─── Severity Helpers ─────────────────────────────────────────────────────────

def score_to_severity(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= settings.CVSS_CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score >= settings.CVSS_HIGH_THRESHOLD:
        return Severity.HIGH
    if score >= settings.CVSS_MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


def parse_severity_string(s: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "NONE": Severity.NONE,
    }
    return mapping.get(s.upper(), Severity.UNKNOWN)


# ─── NVD Parser ───────────────────────────────────────────────────────────────

class NVDParser:
    """Converts raw NVD API JSON into normalized CVERecord objects."""

    def parse_cve(self, raw: Dict[str, Any]) -> CVERecord:
        """
        Parse a single CVE entry from NVD 2.0 API response.
        Handles missing CVSS metrics gracefully.
        """
        try:
            cve_data = raw.get("cve", raw)
            cve_id = cve_data["id"]

            # Description (prefer English)
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # Published / Modified dates
            published_raw = cve_data.get("published", "")
            modified_raw = cve_data.get("lastModified", cve_data.get("published", ""))
            try:
                published = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
                last_modified = datetime.fromisoformat(modified_raw.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published = datetime.utcnow()
                last_modified = datetime.utcnow()

            # CVSS metrics — try v3.1 first, fall back to v3.0, then v2.0
            cvss = None
            severity = Severity.UNKNOWN
            metrics = cve_data.get("metrics", {})

            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    primary = next((m for m in metric_list if m.get("type") == "Primary"), metric_list[0])
                    cvss_data = primary.get("cvssData", {})
                    base_score = cvss_data.get("baseScore")
                    if base_score is not None:
                        base_score = float(base_score)
                        severity_str = cvss_data.get("baseSeverity", "")
                        severity = parse_severity_string(severity_str) if severity_str else score_to_severity(base_score)
                        cvss = CVSSMetrics(
                            version=cvss_data.get("version", "3.1"),
                            base_score=base_score,
                            base_severity=severity,
                            attack_vector=cvss_data.get("attackVector"),
                            attack_complexity=cvss_data.get("attackComplexity"),
                            privileges_required=cvss_data.get("privilegesRequired"),
                            confidentiality_impact=cvss_data.get("confidentialityImpact"),
                            integrity_impact=cvss_data.get("integrityImpact"),
                            availability_impact=cvss_data.get("availabilityImpact"),
                            vector_string=cvss_data.get("vectorString"),
                        )
                    break

            # Affected packages from CPE configurations
            affected_packages = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            criteria = cpe_match.get("criteria", "")
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                pkg_name = parts[4]
                                pkg_version = parts[5] if len(parts) > 5 and parts[5] != "*" else None
                                entry = pkg_name
                                if pkg_version:
                                    entry = f"{pkg_name}:{pkg_version}"
                                if entry not in affected_packages:
                                    affected_packages.append(entry)

            # CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    cwe = desc.get("value", "")
                    if cwe and cwe not in cwe_ids:
                        cwe_ids.append(cwe)

            # References (first 10 only)
            references = [r.get("url", "") for r in cve_data.get("references", [])[:10] if r.get("url")]

            return CVERecord(
                cve_id=cve_id,
                description=description,
                published=published,
                last_modified=last_modified,
                cvss=cvss,
                severity=severity,
                affected_packages=affected_packages,
                cwe_ids=cwe_ids,
                references=references,
            )

        except (KeyError, TypeError, ValueError) as e:
            cve_id = raw.get("cve", {}).get("id", "UNKNOWN")
            raise NVDParseException(str(e), cve_id)

    def build_embedding_document(self, cve: CVERecord) -> str:
        """
        Build a rich text document for embedding.
        Includes CVE ID, description, severity, affected packages, and CWEs.
        More context = better semantic matching.
        """
        parts = [
            f"CVE ID: {cve.cve_id}",
            f"Severity: {cve.severity.value}",
        ]
        if cve.cvss:
            parts.append(f"CVSS Score: {cve.cvss.base_score}")
            if cve.cvss.attack_vector:
                parts.append(f"Attack Vector: {cve.cvss.attack_vector}")
        parts.append(f"Description: {cve.description}")
        if cve.affected_packages:
            parts.append(f"Affected Packages: {', '.join(cve.affected_packages[:10])}")
        if cve.cwe_ids:
            parts.append(f"Weakness Types: {', '.join(cve.cwe_ids)}")
        return "\n".join(parts)


# ─── NVD Ingestion Service ────────────────────────────────────────────────────

class NVDIngestionService:
    """
    Orchestrates NVD CVE ingestion pipeline:
    fetch → parse → deduplicate → embed → persist
    """

    def __init__(self, risk_repository, chroma_collection):
        self.repository = risk_repository
        self.collection = chroma_collection
        self.parser = NVDParser()
        self.http_client = httpx.AsyncClient(timeout=settings.NVD_REQUEST_TIMEOUT)
        logger.info("NVDIngestionService initialized")

    def _get_existing_cve_ids(self) -> set:
        """Fetch all CVE IDs already in ChromaDB to avoid re-embedding."""
        try:
            existing = self.collection.get(include=["metadatas"])
            return {m.get("cve_id") for m in existing.get("metadatas", []) if m.get("cve_id")}
        except Exception as e:
            logger.warning(f"Could not fetch existing CVE IDs from ChromaDB: {e}")
            return set()

    async def _load_sample_data(self) -> List[Dict]:
        """Load sample NVD feed from bundled fixture file."""
        try:
            with open(settings.SAMPLE_NVD_FEED_PATH, "r") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities", [])
            logger.info(f"Loaded {len(vulns)} CVEs from sample fixture")
            return vulns
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise NVDFetchException(f"Failed to load sample NVD data: {e}")

    @retry(
        stop=stop_after_attempt(settings.LLM_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        retry=retry_if_exception_type(httpx.TransportError),
    )
    async def _fetch_from_nvd_api(
        self, keyword: Optional[str] = None, days_back: int = 30, max_results: int = 100
    ) -> List[Dict]:
        """Fetch CVEs from NVD REST API v2.0 with optional keyword filter."""
        headers = {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}
        pub_start = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

        params = {
            "resultsPerPage": min(max_results, settings.NVD_RESULTS_PER_PAGE),
            "startIndex": 0,
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }
        if keyword:
            params["keywordSearch"] = keyword

        all_vulns = []
        try:
            logger.info(f"Fetching CVEs from NVD API | keyword={keyword} days_back={days_back}")
            while len(all_vulns) < max_results:
                response = await self.http_client.get(
                    settings.NVD_API_BASE_URL,
                    params=params,
                    headers=headers,
                )
                if response.status_code == 403:
                    raise NVDFetchException("NVD API rate limit exceeded — add NVD_API_KEY for higher limits", 403)
                if response.status_code != 200:
                    raise NVDFetchException(f"NVD API returned {response.status_code}", response.status_code)

                data = response.json()
                vulns = data.get("vulnerabilities", [])
                all_vulns.extend(vulns)
                total = data.get("totalResults", 0)

                logger.debug(f"NVD page fetched | count={len(vulns)} total={total} so_far={len(all_vulns)}")
                if len(all_vulns) >= total or len(all_vulns) >= max_results or not vulns:
                    break

                params["startIndex"] += len(vulns)
                await asyncio.sleep(0.7)  # NVD rate limit: 5 requests per 30s without key

            logger.info(f"NVD fetch complete | total={len(all_vulns)} CVEs")
            return all_vulns[:max_results]

        except httpx.TimeoutException:
            raise NVDFetchException(f"NVD API timeout after {settings.NVD_REQUEST_TIMEOUT}s")
        except httpx.ConnectError as e:
            raise NVDFetchException(f"Cannot connect to NVD API: {str(e)}")

    def _embed_batch(self, cves: List[CVERecord], batch_size: int = 50) -> Tuple[int, int]:
        """
        Embed a batch of CVEs into ChromaDB.
        Returns (embedded_count, failed_count).
        """
        embedded = 0
        failed = 0
        existing_ids = self._get_existing_cve_ids()

        for i in range(0, len(cves), batch_size):
            batch = cves[i:i + batch_size]
            ids, documents, metadatas = [], [], []

            for cve in batch:
                if cve.cve_id in existing_ids:
                    continue

                doc = self.parser.build_embedding_document(cve)
                ids.append(cve.cve_id)
                documents.append(doc)
                metadatas.append({
                    "cve_id": cve.cve_id,
                    "severity": cve.severity.value,
                    "cvss_score": str(cve.cvss.base_score) if cve.cvss else "0",
                    "affected_packages": json.dumps(cve.affected_packages[:20]),
                    "published": cve.published.isoformat(),
                    "description_preview": cve.description[:300],
                })

            if not ids:
                continue

            try:
                self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
                embedded += len(ids)
                logger.debug(f"Embedded batch | count={len(ids)} total_so_far={embedded}")
            except Exception as e:
                logger.error(f"ChromaDB embed batch failed: {e}")
                failed += len(ids)

        return embedded, failed

    async def ingest(
        self,
        use_sample_data: bool = False,
        keyword_filter: Optional[str] = None,
        days_back: int = 30,
        max_results: int = 100,
    ) -> NVDIngestResponse:
        """Main ingestion pipeline entry point."""
        start_time = time.time()
        ingestion_id = str(uuid.uuid4())
        logger.info(f"NVD ingestion started | id={ingestion_id} sample={use_sample_data}")

        # Step 1: Fetch
        if use_sample_data:
            raw_vulns = await self._load_sample_data()
        else:
            raw_vulns = await self._fetch_from_nvd_api(keyword_filter, days_back, max_results)

        total_fetched = len(raw_vulns)

        # Step 2: Parse
        cves: List[CVERecord] = []
        parse_failures = 0
        for raw in raw_vulns:
            try:
                cve = self.parser.parse_cve(raw)
                cves.append(cve)
            except NVDParseException as e:
                logger.warning(f"Parse failed: {e.detail}")
                parse_failures += 1

        # Step 3: Deduplicate + Embed
        existing_ids = self._get_existing_cve_ids()
        new_cves = [c for c in cves if c.cve_id not in existing_ids]
        skipped = len(cves) - len(new_cves)

        embedded, embed_failures = self._embed_batch(new_cves)
        total_failed = parse_failures + embed_failures

        # Step 4: Persist to PostgreSQL
        await self.repository.save_ingestion_log(
            ingestion_id=ingestion_id,
            source="sample_data" if use_sample_data else "nvd_api",
            total_fetched=total_fetched,
            total_embedded=embedded,
            total_skipped=skipped,
            failed_count=total_failed,
            duration_ms=round((time.time() - start_time) * 1000, 2),
        )

        await self.repository.upsert_cve_records(cves)

        collection_total = self.collection.count()
        duration_ms = round((time.time() - start_time) * 1000, 2)

        logger.info(
            f"NVD ingestion complete | id={ingestion_id} "
            f"fetched={total_fetched} embedded={embedded} "
            f"skipped={skipped} failed={total_failed} "
            f"collection_total={collection_total} ms={duration_ms}"
        )

        return NVDIngestResponse(
            ingestion_id=ingestion_id,
            total_fetched=total_fetched,
            total_embedded=embedded,
            total_skipped_duplicates=skipped,
            failed_count=total_failed,
            duration_ms=duration_ms,
            collection_total=collection_total,
            timestamp=datetime.utcnow(),
        )
