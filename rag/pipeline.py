from openai import AsyncOpenAI

from rag.loader import load_all
from rag.chunker import chunk_all
from rag.embedder import embed_chunks
from rag.vector_store import (
    store_chunks,
    get_count
)
from rag.retriever import (
    retrieve,
    format_for_prompt,
    extract_rag_sources
)


# ══════════════════════════════════════════════
# SETUP RAG
# يشتغل مرة واحدة عند بدء التطبيق
# ══════════════════════════════════════════════

async def setup_rag(api_key: str):
    """
    Setup the complete RAG pipeline:
    1. Load documents
    2. Chunk documents
    3. Generate embeddings
    4. Store in ChromaDB
    """

    existing = get_count()

    if existing > 0:
        print(
            f"✅ RAG already initialized "
            f"({existing} chunks)"
        )
        return

    client = AsyncOpenAI(
        api_key=api_key
    )

    # Step 1: Load Knowledge Base
    docs = await load_all()

    if not docs:
        raise RuntimeError(
            "No documents loaded from knowledge sources."
        )

    print(
        f"✅ Loaded {len(docs)} documents"
    )

    # Step 2: Chunk Documents
    chunks = chunk_all(docs)

    if not chunks:
        raise RuntimeError(
            "No chunks generated."
        )

    print(
        f"✅ Generated {len(chunks)} chunks"
    )

    # Step 3: Generate Embeddings
    embeddings = await embed_chunks(
        chunks,
        client
    )

    if len(embeddings) != len(chunks):
        raise RuntimeError(
            "Embeddings count mismatch."
        )

    print(
        f"✅ Generated {len(embeddings)} embeddings"
    )

    # Step 4: Store in Chroma
    store_chunks(
        chunks,
        embeddings
    )

    print(
        "✅ RAG setup completed successfully!"
    )


# ══════════════════════════════════════════════
# RAW RETRIEVAL RESULTS
# يرجع SearchResult objects
# ══════════════════════════════════════════════

async def query_rag_raw(
    cve_id     : str,
    vuln_type  : str,
    description: str,
    api_key    : str
):
    """
    Retrieve raw SearchResult objects
    from the knowledge base.
    """

    client = AsyncOpenAI(
        api_key=api_key
    )

    results = await retrieve(
        cve_id=cve_id,
        vuln_type=vuln_type,
        description=description,
        client=client
    )

    return results


# ══════════════════════════════════════════════
# PROMPT READY CONTEXT
# يرجع نص جاهز للـ LLM Prompt
# ══════════════════════════════════════════════

async def query_rag(
    cve_id     : str,
    vuln_type  : str,
    description: str,
    api_key    : str
) -> str:
    """
    Retrieve relevant knowledge base context
    and format it for LLM prompts.
    """

    results = await query_rag_raw(
        cve_id=cve_id,
        vuln_type=vuln_type,
        description=description,
        api_key=api_key
    )

    return format_for_prompt(
        results
    )


# ══════════════════════════════════════════════
# CONTEXT + SOURCES (للـ References)
# يرجع النص الجاهز للـ prompt + قائمة منظمة بالمصادر
# (NVD/CISA_KEV/MITRE_ATTACK/CWE/CAPEC) اللي تم السرش فيها،
# عشان الـ Action Agent يضيفها في references بدقة
# ══════════════════════════════════════════════

async def query_rag_with_sources(
    cve_id     : str,
    vuln_type  : str,
    description: str,
    api_key    : str
) -> dict:
    """
    Retrieve both the prompt-ready context string AND a
    structured list of RAG sources used (for references).
    """

    results = await query_rag_raw(
        cve_id=cve_id,
        vuln_type=vuln_type,
        description=description,
        api_key=api_key
    )

    return {
        "context": format_for_prompt(results),
        "sources": extract_rag_sources(results),
    }


# ══════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════

def rag_status() -> dict:
    """
    Returns current RAG status.
    """

    return {
        "stored_chunks": get_count(),
        "status": (
            "ready"
            if get_count() > 0
            else "empty"
        )
    }
