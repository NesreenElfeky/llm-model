from pydantic import BaseModel
from typing import Dict, Any, Optional
from enum import Enum


# ══════════════════════════════════════════════
# SOURCE TYPES
# ══════════════════════════════════════════════

class SourceType(str, Enum):
    NVD          = "nvd"
    CISA_KEV     = "cisa_kev"
    MITRE_ATTACK = "mitre_attack"
    CWE          = "cwe"
    CAPEC        = "capec"


# ══════════════════════════════════════════════
# RETRIEVAL RELEVANCE
# ══════════════════════════════════════════════

class RelevanceLevel(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


# ══════════════════════════════════════════════
# RAW DOCUMENT
# Loader Output
# ══════════════════════════════════════════════

class KnowledgeDocument(BaseModel):
    id       : str
    source   : SourceType
    text     : str
    metadata : Dict[str, Any]


# ══════════════════════════════════════════════
# CHUNK
# Chunker Output
# ══════════════════════════════════════════════

class DocumentChunk(BaseModel):
    id           : str
    doc_id       : str
    source       : SourceType
    text         : str
    metadata     : Dict[str, Any]
    chunk_index  : int
    embedding_id : Optional[str] = None


# ══════════════════════════════════════════════
# RETRIEVER OUTPUT
# ══════════════════════════════════════════════

class SearchResult(BaseModel):
    chunk     : DocumentChunk
    score     : float
    relevance : RelevanceLevel
