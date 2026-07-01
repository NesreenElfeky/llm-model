"""
Orchestrator Workflow

نقطة الدخول الرئيسية للمشروع كله. بياخد الـ raw outputs
من الـ 3 موديلات (Threat Intelligence + Pen Test + Prediction)
زي ما هما (أي شكل كانوا)، ويرجّع النتيجة النهائية الكاملة:
List[dict] فيها الـ 14 output لكل CVE، مرتبة بالأولوية.

Workflow:
    1. Normalize (threat + pentest + prediction)
    2. Build RAG context لكل CVE
    3. multi_cve_pipeline.run_analysis_for_all_cves()
       (وده بدوره بيتعامل مع Memory تلقائياً)
    4. رجوع النتيجة النهائية
"""

import logging
from typing import List, Dict, Any, Optional

from normalizers.threat_normalizer import normalize_threat_intelligence
from normalizers.pentest_normalizer import normalize_pentest
from normalizers.prediction_normalizer import normalize_prediction

from orchestrator.rag_step import build_rag_context_per_cve

from llm.multi_cve_pipeline import run_analysis_for_all_cves

logger = logging.getLogger(__name__)


async def run_orchestrated_analysis(
    threat_intelligence_raw: List[dict],
    pen_test_raw: Any,              # dict واحد أو List[dict] — أي من 3 الأشكال
    predictions_raw: Any,           # dict واحد أو List[dict]
    api_key: Optional[str] = None,
    use_rag: bool = True,
    use_memory: bool = True,
    run_concurrently: bool = True
) -> List[Dict[str, Any]]:
    """
    نقطة الدخول الرئيسية. بترجع List[dict] — كل عنصر فيه
    الـ 14 output لـ CVE واحدة، مرتبة من priority_rank=1
    (الأعلى أولوية) للأقل.
    """

    # ══════════════════════════════════════════════
    # 1) NORMALIZE
    # ══════════════════════════════════════════════

    logger.info("Step 1: Normalizing raw inputs...")

    threat_records     = normalize_threat_intelligence(threat_intelligence_raw)
    pentest_records    = normalize_pentest(pen_test_raw)
    prediction_records = normalize_prediction(predictions_raw)

    logger.info(
        "Normalized: %d CVE(s), %d pentest scan(s), %d prediction(s)",
        len(threat_records), len(pentest_records), len(prediction_records)
    )

    if not threat_records:
        logger.warning("No CVEs found in threat intelligence — returning empty result")
        return []

    # ══════════════════════════════════════════════
    # 2) RAG CONTEXT (لكل CVE على حدة)
    # ══════════════════════════════════════════════

    rag_context_per_cve = {}

    if use_rag:
        logger.info("Step 2: Building RAG context per CVE...")
        try:
            rag_context_per_cve = await build_rag_context_per_cve(
                threat_records=threat_records,
                api_key=api_key
            )
        except Exception as e:
            logger.warning("RAG step failed entirely: %s — continuing without RAG", e)
            rag_context_per_cve = {}
    else:
        logger.info("Step 2: RAG disabled (use_rag=False)")

    # ══════════════════════════════════════════════
    # 3) RUN ANALYSIS FOR ALL CVEs
    #    (Memory بيتم التعامل معاها تلقائياً جوه multi_cve_pipeline)
    # ══════════════════════════════════════════════

    logger.info("Step 3: Running analysis for all CVEs...")

    results = await run_analysis_for_all_cves(
        threat_records=threat_records,
        pentest_records=pentest_records,
        prediction_records=prediction_records,
        rag_context_per_cve=rag_context_per_cve,
        api_key=api_key,
        run_concurrently=run_concurrently,
        use_memory=use_memory
    )

    logger.info(
        "Analysis complete: %d/%d CVE(s) succeeded",
        len(results), len(threat_records)
    )

    return results
