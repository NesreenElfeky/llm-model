"""
Action Agent Wrapper
"""

from typing import Dict, Any, List, Optional
from llm.action_call import run_action_call

REQUIRED_KEYS = ["priority", "mitigation", "references", "full_report"]


async def run_action_agent(
    analysis_output: Dict[str, Any],
    threat_record: Dict[str, Any],
    pentest_records: List[Dict[str, Any]],
    critical_vulnerabilities: List[Dict[str, Any]],
    risk_score_data: Dict[str, Any],
    financial_data: Dict[str, Any],
    rag_context: str,
    rag_sources: Optional[List[Dict[str, Any]]] = None,
    client=None
) -> Dict[str, Any]:

    rag_sources = rag_sources or []

    result = await run_action_call(
        analysis_output=analysis_output,
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=financial_data,
        rag_context=rag_context,
        rag_sources=rag_sources,
        client=client
    )

    # =========================
    # VALIDATION (enhanced)
    # =========================
    missing = [k for k in REQUIRED_KEYS if k not in result]
    if missing:
        raise ValueError(f"Action Agent missing keys: {missing}")

    # =========================
    # ENSURE mitigation structure
    # =========================
    # ملاحظة: run_action_call() بالفعل بتتحقق إن كل mitigation
    # عبارة عن object كامل بكل الحقول (بما فيها pros/cons غير
    # فاضية). الـ normalize هنا طبقة حماية إضافية فقط — بتتعامل
    # بأمان لو عنصر معين جه بشكل غير متوقع (مثلاً string بدل dict)
    # بدل ما تكسر بـ AttributeError، وبتحافظ على "rank" اللي
    # كانت بتضيع قبل كده.

    mitigation = result.get("mitigation", [])

    normalized_mitigation = []

    for i, m in enumerate(mitigation, start=1):

        if not isinstance(m, dict):
            raise ValueError(
                f"Mitigation #{i} expected an object, got "
                f"{type(m).__name__}: {m!r}"
            )

        normalized_mitigation.append({
            "rank": m.get("rank", i),
            "solution": m.get("solution"),
            "description": m.get("description"),
            "pros": m.get("pros", []),
            "cons": m.get("cons", []),
            "effort": m.get("effort"),
            "impact": m.get("impact"),
        })

    result["mitigation"] = normalized_mitigation

    return result
