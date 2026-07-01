"""
API Models

شكل الـ Request اللي بيوصل من الموديلات التلاتة (Threat
Intelligence + Pen Test + Prediction)، وشكل الـ Response
النهائي اللي السيستم بيرجعه.

ملاحظة: الـ raw inputs مرنة عمداً (Any/dict/list) لأن كل
موديل بيرجع شكل مختلف، والـ Normalizers هي المسؤولة عن
التوحيد — مش الـ API layer.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════
# REQUEST
# ══════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    threat_intelligence: List[Dict[str, Any]] = Field(
        ..., description="Raw output from the Threat Intelligence model (list of CVEs)"
    )

    pen_test: Any = Field(
        ..., description="Raw output from the Pen Test model (any of the 3 known shapes)"
    )

    predictions: Any = Field(
        ..., description="Raw output from the Prediction model (dict or list)"
    )

    use_rag: bool = Field(default=True, description="Enable RAG context lookup")
    use_memory: bool = Field(default=True, description="Enable long-term memory")


# ══════════════════════════════════════════════
# RESPONSE — الـ 14 output (+ memory_alert) لكل CVE
# ══════════════════════════════════════════════

class MitigationOption(BaseModel):
    rank: int
    solution: str
    description: str
    pros: List[str]
    cons: List[str]
    effort: str
    impact: str


class ReferenceItem(BaseModel):
    type: str
    id: str
    description: str


class CriticalVulnerability(BaseModel):
    asset_id: Optional[str] = None
    cve_id: Optional[str] = None


class FinancialLoss(BaseModel):
    asset_id: Optional[str] = None
    financial_loss: Optional[float] = None
    low_interval: Optional[float] = None
    high_interval: Optional[float] = None


class CVEAnalysisResult(BaseModel):
    memory_alert: str

    cve_id: Optional[str] = None
    asset_id: Optional[str] = None

    critical_vulnerabilities: List[CriticalVulnerability] = []
    risk_category: Optional[str] = None
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    financial_loss: FinancialLoss

    executive_summary: str
    risk_assessment: str
    simple_explanation: str
    technical_explanation: str
    attack_path: str
    financial_impact: str

    priority: str
    mitigation: List[MitigationOption]
    references: List[ReferenceItem]
    full_report: str

    priority_rank: Optional[int] = None


class AnalyzeResponse(BaseModel):
    results: List[CVEAnalysisResult]
    total_cves: int
    succeeded: int
    pdf_url: Optional[str] = None


# ══════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════

class HealthResponse(BaseModel):
    status: str
    rag_status: Optional[dict] = None
