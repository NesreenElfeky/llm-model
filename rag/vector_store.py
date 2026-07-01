import os
import json
import chromadb

from typing import (
    List,
    Tuple
)

from rag.models import (
    DocumentChunk
)


# ══════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════

CHROMA_HOST = os.getenv(
    "CHROMA_HOST",
    "localhost"
)

CHROMA_PORT = int(
    os.getenv(
        "CHROMA_PORT",
        "8000"
    )
)

COLLECTION_NAME = (
    "cyber_knowledge_base"
)


# ══════════════════════════════════════════════
# CLIENT
# ══════════════════════════════════════════════

def get_client():

    import chromadb

    client = chromadb.PersistentClient(path="./chroma_db")

import chromadb

PERSIST_DIR = "./chroma_db"

def get_collection():
    client = chromadb.PersistentClient(path=PERSIST_DIR)

    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )
# ══════════════════════════════════════════════
# DEVELOPMENT ONLY
# ══════════════════════════════════════════════

def reset_collection():

    client = get_client()

    try:
        client.delete_collection(
            COLLECTION_NAME
        )

        print(
            "🗑 Collection deleted"
        )

    except Exception:
        pass


# ══════════════════════════════════════════════
# STORE
# ══════════════════════════════════════════════

def store_chunks(
    chunks    : List[DocumentChunk],
    embeddings: List[List[float]]
):

    if len(chunks) != len(embeddings):
        raise ValueError(
            f"Chunks ({len(chunks)}) "
            f"!= Embeddings ({len(embeddings)})"
        )

    collection = get_collection()

    existing = collection.count()

    if existing > 0:

        print(
            f"✅ Chroma already contains "
            f"{existing} chunks"
        )

        return

    ids = [
        chunk.id
        for chunk in chunks
    ]

    documents = [
        chunk.text
        for chunk in chunks
    ]

    metadatas = []

    for chunk in chunks:

        metadata = {
            "doc_id"     : chunk.doc_id,
            "source"     : chunk.source.value,
            "chunk_index": chunk.chunk_index,
            **{
                k: (
                    json.dumps(v)
                    if isinstance(
                        v,
                        (dict, list)
                    )
                    else str(v)
                )
                for k, v in chunk.metadata.items()
            }
        }

        metadatas.append(
            metadata
        )

    batch_size = 500

    for i in range(
        0,
        len(chunks),
        batch_size
    ):

        collection.add(
            ids=ids[
                i:i + batch_size
            ],
            embeddings=embeddings[
                i:i + batch_size
            ],
            documents=documents[
                i:i + batch_size
            ],
            metadatas=metadatas[
                i:i + batch_size
            ]
        )

        print(
            f"✅ Stored batch "
            f"{i // batch_size + 1}"
        )

    print(
        f"✅ Vector Store: "
        f"{len(chunks)} chunks stored"
    )


# ══════════════════════════════════════════════
# SEARCH
# ══════════════════════════════════════════════

def search(
    query_embedding: List[float],
    top_k          : int = 5
) -> Tuple[
    List[str],
    List[dict],
    List[float]
]:

    collection = get_collection()

    results = collection.query(
        query_embeddings=[
            query_embedding
        ],
        n_results=top_k,
        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )

    documents = (
        results["documents"][0]
    )

    metadatas = (
        results["metadatas"][0]
    )

    scores = [
        round(
            1 - d,
            4
        )
        for d in results["distances"][0]
    ]

    return (
        documents,
        metadatas,
        scores
    )


# ══════════════════════════════════════════════
# COUNT
# ══════════════════════════════════════════════

def get_count() -> int:

    return (
        get_collection()
        .count()
    )
