# POC-04: Supply Chain Risk Intelligence

> **Pillar 1 — AI-Driven Cyber & Risk Management**  
> Stack: FastAPI · PostgreSQL · Redis · ChromaDB · Claude LLM · Docker

---

## Executive Summary

A production-grade RAG pipeline that ingests NIST National Vulnerability Database (NVD) CVE feeds into a ChromaDB vector store and semantically correlates them against vendor SBOM (Software Bill of Materials) manifests. For each vulnerable dependency discovered, an LLM generates CVSS-scored, actionable remediation guidance. The result is a full risk report — from raw SBOM JSON to executive summary — in seconds.

---

## ROI & Business Impact

| Metric | Manual Process | This POC |
|---|---|---|
| Time to analyze a 100-component SBOM | 3–5 days (security engineer) | < 60 seconds |
| CVE coverage | Limited to known packages | Full NVD corpus (240K+ CVEs) |
| Remediation advice quality | Generic, copy-paste | Context-aware, per-version |
| Cost per SBOM analysis | $500–$2,000 (labor) | ~$0.10 (LLM tokens) |
| Integration with CI/CD | Manual gate | REST API — plug into any pipeline |
| SCA tool licensing | $30K–$150K/year (Snyk, Veracode) | Self-hosted, zero license cost |

**Bottom line**: Replaces expensive SCA (Software Composition Analysis) licensing for organizations willing to self-host. Enables shift-left security — every PR can trigger a SBOM scan. A single critical CVE caught before production deployment prevents an average breach cost of **$4.88M** (IBM 2024).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Two-Phase Pipeline                     │
└─────────────────────────────────────────────────────────┘

Phase 1 — INGEST (one-time / scheduled):
  NVD API / Sample Feed
        │
        ▼
  NVDIngestionService
  ├── Fetch CVEs (httpx + retry)
  ├── Parse NVD JSON → CVERecord (Pydantic)
  ├── Deduplicate (check ChromaDB existing IDs)
  ├── Build embedding documents (CVE ID + severity + description + packages)
  └── Upsert into ChromaDB (cosine similarity index)
        │
        ▼
  ┌──────────┐   ┌───────────────┐
  │ ChromaDB │   │  PostgreSQL   │
  │ (vectors)│   │ (cve_records) │
  └──────────┘   └───────────────┘

Phase 2 — CORRELATE + SCORE (per SBOM submission):
  SBOM Manifest (CycloneDX/SPDX JSON)
        │
        ▼
  SBOMCorrelationService
  ├── Per component: build semantic query
  ├── ChromaDB RAG retrieval (top-K nearest CVEs)
  ├── Post-filter: package name match gate
  └── Returns: {component → [MatchedCVE]}
        │
        ▼
  RiskScoringService
  ├── CVSS-based severity bucketing (deterministic)
  ├── Claude LLM → per-component remediation advice
  ├── Claude LLM → CISO executive summary
  └── Aggregate risk score (weighted CVSS average)
        │
        ▼
  SBOMRiskReport → FastAPI Response + PostgreSQL persistence
```

---

## Key Features

- **Full NVD corpus ingestion**: Fetches from NIST NVD REST API v2.0 with pagination, rate-limit handling, and optional API key support
- **Semantic CVE matching**: ChromaDB cosine similarity search matches packages even with name variations (PIL vs Pillow vs pillow)
- **Dual-gate retrieval**: Semantic similarity threshold (0.6) + package name fuzzy match — reduces false positives
- **CVSS-deterministic scoring**: Risk scores computed from real CVSS metrics — no LLM hallucination in scoring
- **LLM remediation**: Claude generates specific upgrade recommendations per package/version pair
- **Sample data mode**: `use_sample_data: true` — no NVD API key needed for demo/testing
- **Deduplication**: Re-ingesting the same CVE feed skips already-embedded entries
- **CycloneDX / SPDX / Generic**: Flexible SBOM format support via Pydantic schema

---

## Project Structure

```
poc4_supply_chain_risk/
├── app/
│   ├── main.py                              # FastAPI app, 7 exception handlers, lifespan
│   ├── api/routes/__init__.py               # /ingest /sbom/analyze /query /dashboard /scans
│   ├── core/
│   │   ├── config.py                        # All settings (NVD URL, ChromaDB, RAG thresholds)
│   │   ├── database.py                      # PostgreSQL + ChromaDB + Redis init
│   │   └── exceptions.py                   # NVDFetchException, SBOMParseException, RAGException…
│   ├── models/risk.py                       # CVERecord, SBOMScan, RiskFinding, IngestionLog ORM
│   ├── schemas/risk.py                      # SBOMManifest, CVERecord, SBOMRiskReport Pydantic v2
│   ├── services/
│   │   ├── nvd_ingestion_service.py         # Fetch → Parse → Deduplicate → Embed pipeline
│   │   ├── sbom_correlation_service.py      # RAG query per SBOM component
│   │   └── risk_scoring_service.py          # CVSS scoring + LLM remediation
│   └── repositories/risk_repository.py     # All PostgreSQL operations
├── data/
│   ├── sample_nvd_feed.json                 # 5 real CVEs for local testing
│   └── sample_sbom.json                     # 10-component CycloneDX SBOM fixture
├── tests/
│   ├── conftest.py
│   ├── test_nvd_ingestion.py               # 15+ NVD parser + ingestion unit tests
│   └── test_sbom_correlation.py            # 25+ correlation, scoring, and API tests
├── docker/
│   ├── Dockerfile
│   └── postgres/init.sql
├── docker-compose.yml                       # API + PostgreSQL + Redis + ChromaDB
├── requirements.txt
└── .env.example
```

---

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Add ANTHROPIC_API_KEY (required for remediation generation)
# Add NVD_API_KEY (optional — raises rate limit from 5 to 50 req/30s)

# 2. Start all services
docker-compose up --build -d

# 3. Health check
curl http://localhost:8004/health

# 4a. Ingest sample CVEs (no API key needed)
curl -X POST http://localhost:8004/api/v1/risk/ingest \
  -H "Content-Type: application/json" \
  -d '{"use_sample_data": true}'

# 4b. Ingest from live NVD API (requires NVD_API_KEY in .env for best results)
curl -X POST http://localhost:8004/api/v1/risk/ingest \
  -H "Content-Type: application/json" \
  -d '{"use_sample_data": false, "keyword_filter": "python", "days_back": 30, "max_results": 100}'

# 5. Analyze sample SBOM (uses bundled fixture)
curl -X POST http://localhost:8004/api/v1/risk/sbom/analyze \
  -H "Content-Type: application/json" \
  -d '{"use_sample_data": true, "include_remediation": true}'

# 6. Analyze your own SBOM
curl -X POST http://localhost:8004/api/v1/risk/sbom/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sbom": {
      "format": "CycloneDX",
      "metadata": {"application_name": "my-api", "application_version": "1.0.0"},
      "components": [
        {"name": "urllib3", "version": "1.26.14", "purl": "pkg:pypi/urllib3@1.26.14"},
        {"name": "cryptography", "version": "41.0.3", "purl": "pkg:pypi/cryptography@41.0.3"}
      ]
    },
    "include_remediation": true
  }'

# 7. Spot-check a single package
curl -X POST http://localhost:8004/api/v1/risk/query \
  -H "Content-Type: application/json" \
  -d '{"package_name": "urllib3", "package_version": "1.26.14", "top_k": 5}'
```

---

## API Reference

| Method | Endpoint | Rate Limit | Description |
|---|---|---|---|
| `POST` | `/api/v1/risk/ingest` | 5/min | Ingest CVEs from NVD into ChromaDB |
| `POST` | `/api/v1/risk/sbom/analyze` | 10/min | Full SBOM risk analysis |
| `POST` | `/api/v1/risk/query` | 30/min | Query CVE store for single package |
| `GET` | `/api/v1/risk/dashboard` | 20/min | Aggregate risk dashboard |
| `GET` | `/api/v1/risk/scans` | 20/min | SBOM scan history |
| `GET` | `/api/v1/risk/scans/{scan_id}` | 20/min | Specific scan report |
| `GET` | `/api/v1/risk/cve-stats` | — | CVE ingestion statistics |
| `GET` | `/health` | — | Service health check |

---

## ChromaDB Ports

| Service | Port |
|---|---|
| Supply Chain API | `8004` |
| ChromaDB (direct) | `8005` |
| PostgreSQL | `5436` |
| Redis | `6382` |

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v --asyncio-mode=auto
```

---

## Design Decisions

| Decision | Rationale |
|---|---|
| ChromaDB cosine similarity for RAG | Better than keyword search — catches "Pillow" → "PIL" → "pillow" name variants |
| Post-retrieval package name gate | Prevents semantic false positives — "urllib3 HTTP" matching "openssl HTTP" CVEs |
| CVSS scoring is deterministic | Risk scores are auditable math, not LLM inference — critical for compliance |
| LLM for remediation only | Reduces hallucination surface area — LLM never decides severity, only advises |
| Sample data fixture bundled | Zero-dependency demo mode — evaluators don't need NVD API key |
| Deduplication on re-ingest | Safe to run ingestion daily without vector store bloat |

---

*Built as part of the AI Consultant GitHub Portfolio — Pillar 1: AI-Driven Cyber & Risk Management*
