"""
Custom exception hierarchy for Supply Chain Risk Intelligence.
All exceptions inherit from SupplyChainException for centralized handling.
"""
from typing import Optional, List


class SupplyChainException(Exception):
    def __init__(self, detail: str, error_code: str = "SC_ERROR", status_code: int = 500):
        self.detail = detail
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.detail)


class ValidationException(SupplyChainException):
    def __init__(self, detail: str, fields: Optional[List[str]] = None):
        self.fields = fields or []
        super().__init__(detail, "VALIDATION_ERROR", 422)


class NVDFetchException(SupplyChainException):
    """Raised when the NVD API is unreachable or returns unexpected data."""
    def __init__(self, detail: str, status_code_upstream: Optional[int] = None):
        self.status_code_upstream = status_code_upstream
        super().__init__(detail, "NVD_FETCH_ERROR", 503)


class NVDParseException(SupplyChainException):
    """Raised when NVD CVE JSON cannot be parsed into expected schema."""
    def __init__(self, detail: str, cve_id: Optional[str] = None):
        self.cve_id = cve_id
        super().__init__(f"NVD parse error{f' for {cve_id}' if cve_id else ''}: {detail}", "NVD_PARSE_ERROR", 400)


class SBOMParseException(SupplyChainException):
    """Raised when SBOM manifest JSON is malformed or missing required fields."""
    def __init__(self, detail: str, component: Optional[str] = None):
        self.component = component
        super().__init__(f"SBOM parse error{f' at {component}' if component else ''}: {detail}", "SBOM_PARSE_ERROR", 400)


class RAGException(SupplyChainException):
    """Raised on ChromaDB embedding or query failures."""
    def __init__(self, detail: str, operation: str = "query"):
        self.operation = operation
        super().__init__(f"RAG {operation} error: {detail}", "RAG_ERROR", 503)


class RiskScoringException(SupplyChainException):
    """Raised when risk scoring or LLM remediation generation fails."""
    def __init__(self, detail: str):
        super().__init__(detail, "RISK_SCORING_ERROR", 503)


class RepositoryException(SupplyChainException):
    """Raised on PostgreSQL persistence failures."""
    def __init__(self, detail: str, operation: str = "unknown"):
        super().__init__(f"Repository error during '{operation}': {detail}", "REPOSITORY_ERROR", 500)


class SBOMSizeException(SupplyChainException):
    """Raised when SBOM component count exceeds configured limit."""
    def __init__(self, count: int, limit: int):
        super().__init__(
            f"SBOM has {count} components which exceeds maximum of {limit}. Split into smaller manifests.",
            "SBOM_TOO_LARGE", 400
        )
