"""
LLM Pipeline

يحسب الـ risk_extractor outputs مرة واحدة بس لكل CVE، وبعدين
ينادي على الـ Agents (analysis_agent + action_agent) بدل
الاستدعاء المباشر لـ analysis_call/action_call.

ده بيمنع تكرار حساب critical_vulnerabilities / risk_score
/ financial_data — كل واحدة فيهم بتتحسب مرة واحدة بس هنا،
وبتتمرر جاهزة للـ Agents.

يجمع الـ outputs الجاهزة من risk_extractor (بدون LLM) مع
output الـ Agents في 13 من الـ 14 output المتفق عليهم
(priority_rank بيتحسب بعدين في multi_cve_pipeline.py).
"""

from llm.client import get_client

from agents.analysis_agent import run_analysis_agent
from agents.action_agent import run_action_agent

from llm.risk_extractor import (
    extract_critical_vulnerabilities,
    compute_risk_score,
    build_memory_alert
)


def _get_prediction_for_asset(
    asset_id: str,
    prediction_records: list
) -> dict:
    """
    يحاول إيجاد prediction لنفس الـ asset.
    لو مفيش matching يرجع أول prediction متاح.

    بترجع الـ financial_loss الخام (فيها risk_category لازم نستخدمه
    في حساب composite risk score) — التبسيط لـ predicted_cost_usd
    بس بيحصل بعد كده في final_financial_loss أسفل الدالة الرئيسية.
    """

    if not prediction_records:
        return {}

    for record in prediction_records:

        record_asset_id = (
            record.get("asset_id")
            or record.get("threat_intelligence", {}).get("asset_id")
        )

        if (
            asset_id
            and record_asset_id
            and asset_id == record_asset_id
        ):
            return record.get("financial_loss", {})

    return prediction_records[0].get(
        "financial_loss",
        {}
    )


async def run_full_analysis_for_cve(
    threat_record: dict,
    pentest_records: list,
    prediction_records: list,
    all_threat_records: list,
    rag_context: str = "No additional context available.",
    rag_sources: list = None,
    memory_context: list = None,
    api_key: str = None
) -> dict:
    """
    يشغل التحليل الكامل لـ CVE واحدة عن طريق الـ Agents.

    يرجع:
        - Risk Extractor Outputs (محسوبة مرة واحدة بس هنا)
        - Analysis Agent Outputs
        - Action Agent Outputs

    priority_rank لا يتم حسابه هنا.
    يتم حسابه لاحقاً داخل multi_cve_pipeline.py.
    """

    memory_context = memory_context or []
    rag_sources    = rag_sources or []

    client = get_client(api_key)

    ti = threat_record.get(
        "threat_intelligence",
        {}
    )

    asset_id = ti.get("asset_id")

    # ==================================================
    # Risk Extractor (NO LLM) — تتحسب مرة واحدة بس هنا
    # ==================================================

    # الـ financial_loss الخام (فيها risk_category) — تُستخدم
    # داخلياً بس لحساب composite risk score
    raw_financial_loss = _get_prediction_for_asset(
        asset_id,
        prediction_records
    )

    risk_category = raw_financial_loss.get(
        "risk_category"
    )

    risk_score_data = compute_risk_score(
        cvss_score=ti.get("cvss_score"),
        epss_score=ti.get("epss_score"),
        has_public_exploit=ti.get(
            "has_public_exploit"
        ),
        known_ransomware=ti.get(
            "known_ransomware"
        ),
        risk_category=risk_category
    )

    critical_vulnerabilities = (
        extract_critical_vulnerabilities(
            all_threat_records,
            pentest_records
        )
    )

    # الشكل النهائي لـ financial_loss — financial_loss (الرقم)
    # + low_interval + high_interval، ده اللي بيتبعت للـ
    # Agents وبيظهر في الـ output النهائي، مش الـ object الخام
    final_financial_loss = {
        "asset_id"      : asset_id,
        "financial_loss": raw_financial_loss.get("predicted_cost_usd"),
        "low_interval"  : raw_financial_loss.get("prediction_interval_low"),
        "high_interval" : raw_financial_loss.get("prediction_interval_high"),
    }

    # memory_alert — بدون LLM، جملة جاهزة مباشرة من memory_context
    # (هل نفس الـ target/CVE شُوفوا قبل كده؟ وبأي risk_score؟)
    memory_alert = build_memory_alert(
        asset_id=asset_id,
        cve_id=ti.get("cve_id"),
        memory_context=memory_context
    )

    # ==================================================
    # Analysis Agent (يستدعي Call 1 جواه)
    # ==================================================

    analysis_output = await run_analysis_agent(
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=final_financial_loss,
        rag_context=rag_context,
        memory_context=memory_context,
        client=client
    )

    # ==================================================
    # Action Agent (يستدعي Call 2 جواه)
    # ==================================================

    action_output = await run_action_agent(
        analysis_output=analysis_output,
        threat_record=threat_record,
        pentest_records=pentest_records,
        critical_vulnerabilities=critical_vulnerabilities,
        risk_score_data=risk_score_data,
        financial_data=final_financial_loss,
        rag_context=rag_context,
        rag_sources=rag_sources,
        client=client
    )

    # ==================================================
    # Final Output
    # ==================================================

    return {

        # ------------------------------
        # Memory Alert (أول حاجة، قبل أي تحليل)
        # ------------------------------

        "memory_alert":
            memory_alert,

        "cve_id": ti.get("cve_id"),

        "asset_id": asset_id,

        # ------------------------------
        # Risk Extractor
        # ------------------------------

        "critical_vulnerabilities":
            critical_vulnerabilities,

        "risk_category":
            risk_category,

        "risk_score":
            risk_score_data["risk_score"],

        "risk_label":
            risk_score_data["risk_label"],

        "financial_loss":
            final_financial_loss,

        # ------------------------------
        # Analysis Agent
        # ------------------------------

        "executive_summary":
            analysis_output["executive_summary"],

        "risk_assessment":
            analysis_output["risk_assessment"],

        "simple_explanation":
            analysis_output["simple_explanation"],

        "technical_explanation":
            analysis_output["technical_explanation"],

        "attack_path":
            analysis_output["attack_path"],

        "financial_impact":
            analysis_output["financial_impact"],

        # ------------------------------
        # Action Agent
        # ------------------------------

        "priority":
            action_output["priority"],

        "mitigation":
            action_output["mitigation"],

        "references":
            action_output["references"],

        "full_report":
            action_output["full_report"],

        # ------------------------------
        # Orchestrator fills later
        # ------------------------------

        "priority_rank": None
    }
