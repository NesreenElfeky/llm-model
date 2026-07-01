import asyncio

from typing import List

from openai import AsyncOpenAI

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential
)

from rag.models import DocumentChunk


# ══════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════

EMBEDDING_MODEL = "text-embedding-3-small"

BATCH_SIZE = 100


# ══════════════════════════════════════════════
# EMBEDDING API
# ══════════════════════════════════════════════

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=10)
)
async def embed_batch(
    texts : List[str],
    client: AsyncOpenAI
) -> List[List[float]]:
    """
    Create embeddings for a batch of texts.
    """

    response = await client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=texts
    )

    return [
        item.embedding
        for item in response.data
    ]


# ══════════════════════════════════════════════
# EMBED ALL CHUNKS
# ══════════════════════════════════════════════

async def embed_chunks(
    chunks: List[DocumentChunk],
    client: AsyncOpenAI
) -> List[List[float]]:
    """
    Create embeddings for all chunks.
    """

    if not chunks:
        print("⚠️ No chunks provided")
        return []

    # إزالة الـ empty chunks
    valid_chunks = [
        chunk
        for chunk in chunks
        if chunk.text.strip()
    ]

    if len(valid_chunks) != len(chunks):
        print(
            f"⚠️ Removed "
            f"{len(chunks) - len(valid_chunks)} "
            f"empty chunks"
        )

    all_embeddings: List[List[float]] = []

    total_batches = (
        len(valid_chunks)
        + BATCH_SIZE
        - 1
    ) // BATCH_SIZE

    print(
        f"🔄 Embedding "
        f"{len(valid_chunks)} chunks "
        f"in {total_batches} batches..."
    )

    for i in range(
        0,
        len(valid_chunks),
        BATCH_SIZE
    ):

        batch = valid_chunks[
            i:i + BATCH_SIZE
        ]

        texts = [
            chunk.text
            for chunk in batch
        ]

        embeddings = await embed_batch(
            texts,
            client
        )

        all_embeddings.extend(
            embeddings
        )

        batch_num = (
            i // BATCH_SIZE
        ) + 1

        print(
            f"✅ Batch "
            f"{batch_num}/{total_batches}"
        )

    # mismatch check
    if len(all_embeddings) != len(valid_chunks):
        raise ValueError(
            "Embedding count mismatch"
        )

    print(
        f"✅ Embedder: "
        f"{len(all_embeddings)} embeddings created"
    )

    return all_embeddings


# ══════════════════════════════════════════════
# TEST
# ══════════════════════════════════════════════

if __name__ == "__main__":

    from openai import AsyncOpenAI

    async def test():

        chunks = [
            DocumentChunk(
                id="1",
                doc_id="doc1",
                source="cwe",
                text="SQL Injection vulnerability",
                metadata={},
                chunk_index=0
            )
        ]

        client = AsyncOpenAI(
            api_key="YOUR_API_KEY"
        )

        embeddings = await embed_chunks(
            chunks,
            client
        )

        print(
            f"Embedding dimension: "
            f"{len(embeddings[0])}"
        )

    asyncio.run(
        test()
    )
