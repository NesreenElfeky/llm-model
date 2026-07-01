import logging
from openai import AsyncOpenAI

from llm.client import call_llm
from prompts.action_prompt import (
    ACTION_SYSTEM_PROMPT,
    build_action_user_prompt
)

logger = logging.getLogger(__name__)

REQUIRED_KEYS = ["priority", "mitigation", "references", "full_report"]
EXPECTED_MITIGATIONS = 5

# كل mitigation لازم يكون فيها الحقول دي (خصوصاً pros/cons —
# ده أهم تعديل: لازم يبقوا lists غير فاضية، مش بس موجودين)
REQUIRED_MITIGATION_FIELDS = [
    "rank", "solution", "description", "pros", "cons", "effort", "impact"
]


async def run_action_call(
    analysis_output: dict,
    threat_record: dict,
    pentest_records: list,
    critical_vulnerabilities: list,
    risk_score_data: dict,
    financial_data: dict,
    rag_context: str,
    rag_sources: list = None,
    client: AsyncOpenAI = None
):

    rag_sources = rag_sources or []

    ti = threat_record.get("threat_intelligence", {})
    cve_id = ti.get("cve_id")

    logger.info("Running Action Call for CVE: %s", cve_id)

    user_prompt = build_action_user_prompt(
        analysis_output=analysis_output,
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=financial_data,
        rag_context=rag_context,
        rag_sources=rag_sources
    )

    result = await call_llm(
        system_prompt=ACTION_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        client=client
    )

    missing = [k for k in REQUIRED_KEYS if k not in result]

    if missing:
        raise ValueError(f"Action call missing keys: {missing}")

    empty = [
        k for k in REQUIRED_KEYS
        if result.get(k) is None or result.get(k) == ""
    ]

    if empty:
        raise ValueError(f"Action call returned empty values: {empty}")

    # ══════════════════════════════════════════════
    # MITIGATION VALIDATION — لازم تكون objects كاملة
    # بـ pros/cons فعليين، مش نصوص بسيطة أو lists فاضية
    # ══════════════════════════════════════════════

    mitigations = result.get("mitigation", [])

    if not isinstance(mitigations, list):
        raise ValueError("mitigation must be a list")

    if len(mitigations) != EXPECTED_MITIGATIONS:
        logger.warning(
            "Expected %s mitigations, got %s for CVE %s",
            EXPECTED_MITIGATIONS,
            len(mitigations),
            cve_id
        )

    for i, mitigation in enumerate(mitigations):

        if not isinstance(mitigation, dict):
            raise ValueError(
                f"Mitigation #{i} must be an object with "
                f"{REQUIRED_MITIGATION_FIELDS}, got: {type(mitigation).__name__}"
            )

        missing_fields = [
            f for f in REQUIRED_MITIGATION_FIELDS
            if f not in mitigation
        ]

        if missing_fields:
            raise ValueError(
                f"Mitigation #{i} (CVE {cve_id}) missing fields: {missing_fields}"
            )

        pros = mitigation.get("pros")
        cons = mitigation.get("cons")

        if not isinstance(pros, list) or len(pros) == 0:
            raise ValueError(
                f"Mitigation #{i} (CVE {cve_id}) 'pros' must be a "
                f"non-empty list, got: {pros}"
            )

        if not isinstance(cons, list) or len(cons) == 0:
            raise ValueError(
                f"Mitigation #{i} (CVE {cve_id}) 'cons' must be a "
                f"non-empty list, got: {cons}"
            )

    result["_metadata"] = {
        "call_type": "action",
        "cve_id": cve_id,
        "asset_id": ti.get("asset_id")
    }

    logger.info("Action completed for CVE: %s", cve_id)

    return result
