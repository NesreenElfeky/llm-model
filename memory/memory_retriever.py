from typing import Optional, Dict
from .memory_store import MemoryStore


class MemoryRetriever:

    def __init__(self, store: MemoryStore):
        self.store = store

    def check_seen(self, asset_id: str, cve_id: str) -> bool:
        return self.store.has_cve(asset_id, cve_id)

    def get_previous(self, asset_id: str, cve_id: str) -> Optional[Dict]:
        return self.store.get_cve(asset_id, cve_id)

    def get_target_history(self, asset_id: str):
        return self.store.get_target(asset_id)