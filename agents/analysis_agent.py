"""
Analysis Agent

Wrapper حول run_analysis_call() — بيضيف layer تنظيمي ووصفي
("Agent") من غير ما يكرر حسابات risk_extractor.

ملاحظة مهمة: الـ Agent ده ما بيحسبش critical_vulnerabilities
أو risk_score أو financial_data من تلقاء نفسه. دي بتتحسب
مرة واحدة بس في pipeline.py وبتتمرر هنا جاهزة، عشان نمنع
تكرار الحساب لكل CVE (كان بيتكرر مرتين لو كل agent بيحسبها
لوحده).
"""

from typing import Dict, Any, List, Optional

from llm.analysis_call import run_analysis_call


REQUIRED_KEYS = [
    "executive_summary",
    "risk_assessment",
    "simple_explanation",
    "technical_explanation",
    "attack_path",
    "financial_impact"
]


async def run_analysis_agent(
    threat_record: Dict[str, Any],
    pentest_records: List[Dict[str, Any]],
    critical_vulnerabilities: List[Dict[str, Any]],
    risk_score_data: Dict[str, Any],
    financial_data: Dict[str, Any],
    rag_context: str,
    memory_context: Optional[List[Dict[str, Any]]] = None,
    client=None
) -> Dict[str, Any]:
    """
    Analysis Agent:
    - بياخد critical_vulnerabilities / risk_score_data / financial_data
      جاهزين (محسوبين قبل كده في pipeline.py)
    - يشغل analysis_call (LLM call واحد)
    - يرجّع 6 outputs بعد validation
    """

    memory_context = memory_context or []

    result = await run_analysis_call(
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=financial_data,
        rag_context=rag_context,
        memory_context=memory_context,
        client=client
    )

    missing = [k for k in REQUIRED_KEYS if k not in result]
    if missing:
        raise ValueError(f"Analysis Agent missing keys: {missing}")

    return result
