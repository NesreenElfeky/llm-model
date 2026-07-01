"""
RAG Step

بيحسب rag_context + rag_sources لكل CVE على حدة، باستخدام
query_rag_with_sources() الموجودة في rag/pipeline.py.

بيرجع dict بشكل:
    {cve_id: {"context": "...", "sources": [{"source": "NVD", ...}, ...]}}

ده الشكل اللي multi_cve_pipeline.run_analysis_for_all_cves()
متوقعه في rag_context_per_cve (الـ context بيتحط في الـ prompt،
والـ sources بتتمرر للـ Action Agent عشان يضيفها في references).
"""

import asyncio
import logging
from typing import List, Dict, Any

from rag.pipeline import query_rag_with_sources

logger = logging.getLogger(__name__)

DEFAULT_RESULT = {
    "context": "No additional context available.",
    "sources": [],
}


async def build_rag_context_per_cve(
    threat_records: List[dict],
    api_key: str = None
) -> Dict[str, Dict[str, Any]]:
    """
    يسرش في الـ RAG لكل CVE على حدة، ويرجع dict
    {cve_id: {"context": str, "sources": list}}.

    لو الـ RAG فشل لـ CVE معينة (مثلاً Chroma مش متاحة)،
    بيرجع DEFAULT_RESULT بدل ما يوقف كل التحليل.
    """

    async def _get_context_for_one(threat_record: dict) -> tuple:
        ti = threat_record.get("threat_intelligence", {})

        cve_id      = ti.get("cve_id")
        vuln_type   = ti.get("vuln_type", "")
        description = ti.get("description", "")

        try:
            result = await query_rag_with_sources(
                cve_id=cve_id,
                vuln_type=vuln_type,
                description=description,
                api_key=api_key
            )
            return cve_id, result

        except Exception as e:
            logger.warning(
                "RAG lookup failed for %s: %s — using default context",
                cve_id, e
            )
            return cve_id, dict(DEFAULT_RESULT)

    results = await asyncio.gather(
        *[_get_context_for_one(record) for record in threat_records],
        return_exceptions=False
    )

    return {cve_id: result for cve_id, result in results}
