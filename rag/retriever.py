from typing import List, Dict, Any

from openai import AsyncOpenAI
from sentence_transformers import CrossEncoder

from rag.models import (
    DocumentChunk,
    SearchResult,
    SourceType,
    RelevanceLevel
)
from rag.vector_store import search
from rag.embedder import EMBEDDING_MODEL


TOP_K = 5
EXPANDED_TOP_K = 15  # 🔥 بنجيب أكتر الأول وبعدين نrerank

# =========================
# RERANKER MODEL (LOCAL - NO COST)
# =========================
reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")


# ══════════════════════════════════════════════
# RETRIEVER WITH RERANKING
# ══════════════════════════════════════════════

async def retrieve(
    cve_id: str,
    vuln_type: str,
    description: str,
    client: AsyncOpenAI
) -> List[SearchResult]:

    # =========================
    # 1. BUILD QUERY
    # =========================
    query = f"CVE: {cve_id} | Type: {vuln_type} | {description[:200]}"

    # =========================
    # 2. EMBEDDING
    # =========================
    response = await client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=[query]
    )
    query_embedding = response.data[0].embedding

    # =========================
    # 3. VECTOR SEARCH (EXPANDED)
    # =========================
    documents, metadatas, scores = search(
        query_embedding,
        top_k=EXPANDED_TOP_K
    )

    if not documents:
        return []

    # =========================
    # 4. RERANKING STEP (LOCAL MODEL)
    # =========================
    pairs = [(query, doc) for doc in documents]
    rerank_scores = reranker.predict(pairs)

    ranked = sorted(
        zip(documents, metadatas, rerank_scores),
        key=lambda x: x[2],
        reverse=True
    )

    # =========================
    # 5. BUILD FINAL RESULTS (TOP 5)
    # =========================
    results: List[SearchResult] = []

    for i in range(min(TOP_K, len(ranked))):

        doc, meta, score = ranked[i]
        score = float(score)

        # ── RelevanceLevel enum بدل string خام، عشان يطابق
        #    rag/models.py (type safety مع Pydantic) ──
        if score > 0.75:
            relevance = RelevanceLevel.HIGH
        elif score > 0.5:
            relevance = RelevanceLevel.MEDIUM
        else:
            relevance = RelevanceLevel.LOW

        source_value = meta.get("source", "nvd")
        try:
            source = SourceType(source_value)
        except ValueError:
            source = SourceType.NVD

        chunk = DocumentChunk(
            id=meta.get("doc_id", f"chunk-{i}") + f"-{i}",
            doc_id=meta.get("doc_id", ""),
            source=source,
            text=doc,
            metadata=meta,
            chunk_index=int(meta.get("chunk_index", 0))
        )

        results.append(
            SearchResult(
                chunk=chunk,
                score=score,  # reranker score
                relevance=relevance
            )
        )

    return results


# ══════════════════════════════════════════════
# FORMAT FOR PROMPT
# ══════════════════════════════════════════════

def format_for_prompt(results: List[SearchResult]) -> str:

    if not results:
        return "No additional context available."

    formatted = "=== KNOWLEDGE BASE CONTEXT ===\n\n"

    for i, result in enumerate(results, 1):
        formatted += (
            f"[{i}] Source: {result.chunk.source.value.upper()} "
            f"| Relevance: {result.relevance.value} ({round(result.score, 3)})\n"
        )
        formatted += f"{result.chunk.text}\n"
        formatted += "-" * 60 + "\n"

    return formatted


# ══════════════════════════════════════════════
# EXTRACT SOURCES (للـ References)
# بترجع قائمة منظمة بالمصادر اللي تم السرش فيها فعلياً
# (بعد الـ reranking)، عشان الـ Action Agent يقدر يضيفها
# في references بدقة (مش بس نص مدمج زي format_for_prompt)
# ══════════════════════════════════════════════

def extract_rag_sources(
    results: List[SearchResult]
) -> List[Dict[str, Any]]:

    if not results:
        return []

    sources = []
    seen = set()

    for result in results:
        source_name = result.chunk.source.value.upper()

        if source_name not in seen:
            seen.add(source_name)
            sources.append({
                "source": source_name,
                "top_similarity": round(result.score, 3)
            })

    return sources
