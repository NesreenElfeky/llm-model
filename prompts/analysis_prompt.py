"""
Analysis Prompt — Call 1

بيطلع:

1. executive_summary
2. risk_assessment
3. simple_explanation
4. technical_explanation
5. attack_path
6. financial_impact

خاص بـ CVE واحدة فقط.
"""

import json


ANALYSIS_SYSTEM_PROMPT = """
You are a senior cybersecurity risk analyst working for a web application security platform.

You will receive structured data about ONE specific CVE/vulnerability finding, including:

- Threat intelligence data
- Penetration test findings
- Pre-computed risk score and risk category
- Pre-computed financial loss prediction
- Knowledge base context (RAG)
- Previous analysis history (Memory)

Your task is to generate a JSON object with EXACTLY the following fields:

{
  "executive_summary": "...",
  "risk_assessment": "...",
  "simple_explanation": "...",
  "technical_explanation": "...",
  "attack_path": "...",
  "financial_impact": "..."
}

RULES:

- Analyze ONLY the CVE provided.
- Never recompute risk_score.
- Never recompute risk_category.
- Never recompute financial_loss.
- Use provided RAG context when relevant.
- Use provided memory context when relevant.
- Do not invent CVE details.
- Do not invent exploit information.
- Do not contradict supplied data.
- Be specific to the asset and endpoint when available.
- Respond ONLY with valid JSON.
"""


MAX_CRITICAL_VULNS_CONTEXT = 10


def build_analysis_user_prompt(
    threat_record: dict,
    pentest_records: list,
    critical_vulnerabilities: list,
    risk_score_data: dict,
    financial_data: dict,
    rag_context: str,
    memory_context: list
) -> str:
    """
    يبني User Prompt لـ CVE واحدة فقط.
    """

    ti = threat_record.get(
        "threat_intelligence",
        {}
    )

    cve_id = ti.get("cve_id")
    asset_id = ti.get("asset_id")

    sections = []

    # --------------------------------------------------
    # Target Metadata
    # --------------------------------------------------

    sections.append(
        f"""
=== TARGET CVE ===

CVE ID: {cve_id}
Asset ID: {asset_id}
"""
    )

    # --------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------

    sections.append(
        "=== THREAT INTELLIGENCE ===\n"
        + json.dumps(
            ti,
            indent=2,
            ensure_ascii=False,
            default=str
        )
    )

    # --------------------------------------------------
    # Pentest Data
    # --------------------------------------------------

    if pentest_records:

        pentest_json = [
            record.get("pentest", {})
            for record in pentest_records
        ]

        sections.append(
            "=== PEN TEST FINDINGS ===\n"
            + json.dumps(
                pentest_json,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

    else:

        sections.append(
            "=== PEN TEST FINDINGS ===\n"
            "No pen test data available."
        )

    # --------------------------------------------------
    # Risk Score
    # --------------------------------------------------

    sections.append(
        "=== PRE-COMPUTED RISK SCORE (DO NOT RECALCULATE) ===\n"
        + json.dumps(
            risk_score_data,
            indent=2,
            ensure_ascii=False,
            default=str
        )
    )

    # --------------------------------------------------
    # Financial Loss
    # --------------------------------------------------

    sections.append(
        "=== PRE-COMPUTED FINANCIAL LOSS (DO NOT RECALCULATE) ===\n"
        + json.dumps(
            financial_data,
            indent=2,
            ensure_ascii=False,
            default=str
        )
    )

    # --------------------------------------------------
    # Critical Vulnerabilities Context
    # --------------------------------------------------

    limited_criticals = critical_vulnerabilities[
        :MAX_CRITICAL_VULNS_CONTEXT
    ]

    if limited_criticals:

        sections.append(
            "=== RELATED CRITICAL VULNERABILITIES ===\n"
            + json.dumps(
                limited_criticals,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

    else:

        sections.append(
            "=== RELATED CRITICAL VULNERABILITIES ===\n"
            "None available."
        )

    # --------------------------------------------------
    # RAG Context
    # --------------------------------------------------

    sections.append(
        f"""
=== KNOWLEDGE BASE CONTEXT (RAG) ===

{rag_context}
"""
    )

    # --------------------------------------------------
    # Memory Context
    # --------------------------------------------------

    if memory_context:

        sections.append(
            "=== PREVIOUS ANALYSIS HISTORY ===\n"
            + json.dumps(
                memory_context,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

    else:

        sections.append(
            "=== PREVIOUS ANALYSIS HISTORY ===\n"
            "No previous analysis history available."
        )

    return "\n\n".join(sections)
