import logging
from openai import AsyncOpenAI

from llm.client import call_llm
from prompts.analysis_prompt import (
    ANALYSIS_SYSTEM_PROMPT,
    build_analysis_user_prompt
)

logger = logging.getLogger(__name__)

REQUIRED_KEYS = [
    "executive_summary",
    "risk_assessment",
    "simple_explanation",
    "technical_explanation",
    "attack_path",
    "financial_impact"
]


async def run_analysis_call(
    threat_record: dict,
    pentest_records: list,
    critical_vulnerabilities: list,
    risk_score_data: dict,
    financial_data: dict,
    rag_context: str,
    memory_context: list,
    client: AsyncOpenAI
):

    ti = threat_record.get("threat_intelligence", {})
    cve_id = ti.get("cve_id")

    logger.info("Running Analysis Call for CVE: %s", cve_id)

    user_prompt = build_analysis_user_prompt(
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=financial_data,
        rag_context=rag_context,
        memory_context=memory_context
    )

    result = await call_llm(
        system_prompt=ANALYSIS_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        client=client
    )

    missing = [k for k in REQUIRED_KEYS if k not in result]

    if missing:
        raise ValueError(f"Missing keys: {missing}")

    empty = [k for k in REQUIRED_KEYS if result.get(k) in [None, ""]]

    if empty:
        raise ValueError(f"Empty values: {empty}")

    result["_metadata"] = {
        "call_type": "analysis",
        "cve_id": cve_id,
        "asset_id": ti.get("asset_id")
    }

    logger.info("Analysis completed for CVE: %s", cve_id)

    return result