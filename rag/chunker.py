from typing import List

from rag.models import (
    KnowledgeDocument,
    DocumentChunk
)


# ══════════════════════════════════════════════
# CHUNK CONFIGURATION
# حجم مختلف لكل مصدر
# الأحجام هنا بعدد الكلمات وليس الحروف
# ══════════════════════════════════════════════

CHUNK_CONFIG = {
    "nvd": {
        "size"   : 150,
        "overlap": 20
    },
    "cisa_kev": {
        "size"   : 150,
        "overlap": 20
    },
    "mitre_attack": {
        "size"   : 250,
        "overlap": 40
    },
    "cwe": {
        "size"   : 120,
        "overlap": 20
    },
    "capec": {
        "size"   : 150,
        "overlap": 20
    }
}

DEFAULT_CHUNK = {
    "size"   : 150,
    "overlap": 20
}


# ══════════════════════════════════════════════
# CHUNK SINGLE DOCUMENT
# ══════════════════════════════════════════════

def chunk_document(
    doc: KnowledgeDocument
) -> List[DocumentChunk]:

    config = CHUNK_CONFIG.get(
        doc.source.value,
        DEFAULT_CHUNK
    )

    chunk_size = config["size"]
    overlap    = config["overlap"]

    words = doc.text.split()

    chunks: List[DocumentChunk] = []

    start       = 0
    chunk_index = 0

    while start < len(words):

        end = min(
            start + chunk_size,
            len(words)
        )

        chunk_text = " ".join(
            words[start:end]
        ).strip()

        if chunk_text:

            chunks.append(
                DocumentChunk(
                    id=f"{doc.id}-chunk-{chunk_index}",
                    doc_id=doc.id,
                    source=doc.source,
                    text=chunk_text,
                    metadata={
                        **doc.metadata,
                        "chunk_index": chunk_index
                    },
                    chunk_index=chunk_index
                )
            )

            chunk_index += 1

        start += chunk_size - overlap

    # إضافة chunk_count لكل الـ chunks
    total_chunks = len(chunks)

    for chunk in chunks:
        chunk.metadata["chunk_count"] = total_chunks

    return chunks


# ══════════════════════════════════════════════
# CHUNK ALL DOCUMENTS
# ══════════════════════════════════════════════

def chunk_all(
    docs: List[KnowledgeDocument]
) -> List[DocumentChunk]:

    all_chunks: List[DocumentChunk] = []

    for doc in docs:
        all_chunks.extend(
            chunk_document(doc)
        )

    print(
        f"✅ Chunker: "
        f"{len(docs)} documents → "
        f"{len(all_chunks)} chunks"
    )

    return all_chunks


# ══════════════════════════════════════════════
# TEST
# ══════════════════════════════════════════════

if __name__ == "__main__":

    from rag.loader import load_all
    import asyncio

    docs = asyncio.run(
        load_all()
    )

    chunks = chunk_all(
        docs
    )

    print(
        f"Generated {len(chunks)} chunks"
    )

    if chunks:
        print(
            chunks[0].model_dump()
        )
