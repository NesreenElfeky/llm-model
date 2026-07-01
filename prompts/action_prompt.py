"""
Action Prompt — Call 2

بيطلع:
  - priority
  - mitigation
  - references
  - full_report

خاص بـ CVE واحدة فقط. نفس نمط الـ JSON formatting المستخدم
في analysis_prompt.py (json.dumps بدل f-string مباشر على الـ dicts).
"""

import json


ACTION_SYSTEM_PROMPT = """
You are a senior cybersecurity remediation strategist working for a web application security platform.

You will receive the full analysis already generated for ONE specific CVE/vulnerability finding, including:
- Original threat intelligence data
- Penetration testing findings
- Critical vulnerability indicators
- Pre-computed risk score and risk category
- Pre-computed financial loss
- Analysis generated in Call 1
- Knowledge base context (CVE, CWE, CAPEC, MITRE ATT&CK)

Generate EXACTLY the following JSON structure:

{
  "priority": "string",

  "mitigation": [
    {
      "rank": 1,
      "solution": "string",
      "description": "string",
      "pros": ["string","string"],
      "cons": ["string","string"],
      "effort": "Low/Medium/High",
      "impact": "Low/Medium/High"
    }
  ],

  "references": [
    {
      "type": "CVE/MITRE/CWE/CAPEC",
      "id": "string",
      "description": "string"
    }
  ],

  "full_report": "string"
}

RULES:

1. Return EXACTLY 5 mitigation solutions.
2. Rank mitigations from best to least preferred.
3. References must come from the provided context only.
4. Do not invent CVEs, CWEs, CAPECs, ATT&CK techniques, endpoints, products, or vendors.
5. Use the actual risk score and financial loss provided.
6. If endpoint information exists, tailor mitigations to it.
7. EVERY mitigation object MUST include ALL seven fields: rank, solution,
   description, pros, cons, effort, impact. This is mandatory, with no
   exceptions.
8. "pros" MUST be a non-empty list with AT LEAST 2 specific, concrete
   advantages of that exact solution (not generic statements).
9. "cons" MUST be a non-empty list with AT LEAST 2 specific, concrete
   drawbacks or trade-offs of that exact solution (not generic statements).
   A mitigation with no real drawback is rare — think about cost, downtime,
   complexity, compatibility, or residual risk.
10. NEVER return mitigation as a plain string or a list of strings. Each
    mitigation MUST be a full JSON object matching the schema above exactly.
11. EVERY piece of technical/contextual information you used from the
    "KNOWLEDGE BASE CONTEXT (RAG)" section MUST be reflected in references
    with its source. You will be given a "RAG SOURCES USED" list (e.g.
    NVD, CISA_KEV, MITRE_ATTACK, CWE, CAPEC) — add one reference entry per
    distinct source actually used, with "type" set to that source name
    (e.g. "type": "RAG_SOURCE", "id": "NVD"). If RAG SOURCES USED is empty,
    do not invent any RAG-based reference.
12. full_report must combine:
    - Risk Category
    - Risk Score
    - Financial Loss
    - Critical Vulnerability Status
    - Executive Summary
    - Risk Assessment
    - Simple Explanation
    - Technical Explanation
    - Attack Path
    - Financial Impact
    - Priority
    - Mitigation Plan (including each mitigation's pros and cons)
    - References

Respond ONLY with valid JSON.
"""


def build_action_user_prompt(
    analysis_output: dict,
    threat_record: dict,
    pentest_records: list,
    critical_vulnerabilities: list,
    risk_score_data: dict,
    financial_data: dict,
    rag_context: str,
    rag_sources: list = None
) -> str:
    """
    يبني الـ user prompt للـ Action Call.
    نفس نمط json.dumps() المستخدم في analysis_prompt.py.
    """

    rag_sources = rag_sources or []

    ti = threat_record.get("threat_intelligence", {})

    sections = []

    # --------------------------------------------------
    # Analysis Output (from Call 1)
    # --------------------------------------------------

    analysis_text = "\n".join(
        f"[{key.upper()}]\n{value}\n"
        for key, value in analysis_output.items()
    )

    sections.append(
        "=== ANALYSIS OUTPUT (CALL 1) ===\n"
        + analysis_text
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
    # Critical Vulnerabilities
    # --------------------------------------------------

    if critical_vulnerabilities:

        sections.append(
            "=== CRITICAL VULNERABILITIES ===\n"
            + json.dumps(
                critical_vulnerabilities,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )

    else:

        sections.append(
            "=== CRITICAL VULNERABILITIES ===\n"
            "None"
        )

    # --------------------------------------------------
    # Risk Score
    # --------------------------------------------------

    sections.append(
        "=== PRE-COMPUTED RISK SCORE ===\n"
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
        "=== PRE-COMPUTED FINANCIAL LOSS ===\n"
        + json.dumps(
            financial_data,
            indent=2,
            ensure_ascii=False,
            default=str
        )
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
    # RAG Sources (للـ References)
    # --------------------------------------------------

    if rag_sources:
        sections.append(
            "=== RAG SOURCES USED (add one reference per source) ===\n"
            + json.dumps(
                rag_sources,
                indent=2,
                ensure_ascii=False,
                default=str
            )
        )
    else:
        sections.append(
            "=== RAG SOURCES USED ===\n"
            "None — do not invent any RAG-based reference."
        )

    return "\n\n".join(sections)
