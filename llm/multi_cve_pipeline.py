"""
Multi-CVE Pipeline

مسؤول عن تحليل كل CVEs المكتشفة ثم ترتيبها حسب الأولوية.

Workflow:

1. Loop على كل CVE
2. سؤال الـ Memory: هل شفنا الـ CVE دي على نفس الـ asset قبل كده؟
   (عن طريق MemoryRetriever.check_seen / get_previous)
3. تشغيل run_full_analysis_for_cve()
4. حفظ/تحديث النتيجة في Memory (MemoryStore.update_cve)
5. ترتيب النتائج حسب الأولوية

Output:
    List[dict]
"""

import asyncio
from typing import List, Optional

from llm.pipeline import run_full_analysis_for_cve
from llm.risk_extractor import rank_cves_by_priority

from memory.memory_store import MemoryStore
from memory.memory_retriever import MemoryRetriever


async def run_analysis_for_all_cves(
    threat_records: List[dict],
    pentest_records: List[dict],
    prediction_records: List[dict],
    rag_context_per_cve: Optional[dict] = None,
    api_key: str = None,
    run_concurrently: bool = True,
    use_memory: bool = True
) -> List[dict]:

    rag_context_per_cve = rag_context_per_cve or {}

    if not threat_records:
        return []

    #
    # MEMORY SETUP — instance واحدة تُستخدم لكل الـ CVEs
    #
    store = MemoryStore() if use_memory else None
    retriever = MemoryRetriever(store) if use_memory else None

    async def _analyze_one(threat_record: dict) -> dict:

        ti = threat_record.get(
            "threat_intelligence",
            {}
        )

        cve_id = ti.get("cve_id")
        asset_id = ti.get("asset_id")

        filtered_pentest_records = pentest_records

        #
        # RAG — استخراج context (نص للـ prompt) و sources
        # (قائمة منظمة لمصادر RAG، تتمرر للـ Action Agent
        # عشان يضيفها في references)
        #
        rag_entry = rag_context_per_cve.get(
            cve_id,
            {"context": "No additional context available.", "sources": []}
        )
        rag_context_text = rag_entry.get("context", "No additional context available.")
        rag_sources       = rag_entry.get("sources", [])

        #
        # MEMORY (READ) — هل شُوفت الـ CVE دي على الـ asset ده قبل كده؟
        #
        memory_context = []

        if use_memory and asset_id and cve_id:

            seen_before = retriever.check_seen(asset_id, cve_id)

            if seen_before:
                previous = retriever.get_previous(asset_id, cve_id)
                if previous:
                    memory_context = [previous]

        #
        # ANALYSIS
        #
        result = await run_full_analysis_for_cve(
            threat_record=threat_record,
            pentest_records=filtered_pentest_records,
            prediction_records=prediction_records,
            all_threat_records=threat_records,
            rag_context=rag_context_text,
            rag_sources=rag_sources,
            memory_context=memory_context,
            api_key=api_key
        )

        #
        # MEMORY (WRITE) — محمي عشان فشل الحفظ
        # ما يبوظش نتيجة التحليل الصحيحة
        #
        if use_memory and asset_id and cve_id:

            try:
                store.update_cve(
                    asset_id=asset_id,
                    cve_id=cve_id,
                    risk_score=result.get("risk_score"),
                    risk_category=result.get("risk_category")
                )

            except Exception as e:

                print(
                    f"[WARNING] Failed to save memory "
                    f"for {cve_id}: {e}"
                )

        return result

    #
    # RUN ALL CVEs
    #
    if run_concurrently:

        raw_results = await asyncio.gather(
            *[
                _analyze_one(record)
                for record in threat_records
            ],
            return_exceptions=True
        )

    else:

        raw_results = []

        for record in threat_records:

            try:

                result = await _analyze_one(
                    record
                )

                raw_results.append(
                    result
                )

            except Exception as e:

                raw_results.append(
                    e
                )

    #
    # FILTER ERRORS
    #
    successful_results = []

    for result in raw_results:

        if isinstance(
            result,
            Exception
        ):

            print(
                f"[ERROR] CVE analysis failed: "
                f"{result}"
            )

            continue

        successful_results.append(
            result
        )

    #
    # ALL FAILED
    #
    if not successful_results:

        return []

    #
    # RANK RESULTS
    #
    ranked_results = rank_cves_by_priority(
        successful_results
    )

    return ranked_results
