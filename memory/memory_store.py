import json
import os
from typing import Optional
from .memory_schema import TargetMemory, CVEMemoryRecord, to_dict


class MemoryStore:
    """
    Simple JSON-based memory store (MVP).
    """

    def __init__(self, path: str = "memory_store.json"):
        self.path = path
        self._data = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    # -------------------------
    # GET TARGET
    # -------------------------
    def get_target(self, asset_id: str) -> Optional[dict]:
        return self._data.get(asset_id)

    # -------------------------
    # CHECK CVE EXISTS
    # -------------------------
    def has_cve(self, asset_id: str, cve_id: str) -> bool:
        target = self._data.get(asset_id)
        if not target:
            return False

        return any(c["cve_id"] == cve_id for c in target["cves"])

    # -------------------------
    # GET OLD CVE INFO
    # -------------------------
    def get_cve(self, asset_id: str, cve_id: str) -> Optional[dict]:
        target = self._data.get(asset_id)
        if not target:
            return None

        for c in target["cves"]:
            if c["cve_id"] == cve_id:
                return c
        return None

    # -------------------------
    # SAVE / UPDATE
    # -------------------------
    def update_cve(
        self,
        asset_id: str,
        cve_id: str,
        risk_score: float,
        risk_category: str
    ):
        if asset_id not in self._data:
            self._data[asset_id] = {
                "asset_id": asset_id,
                "cves": []
            }

        # لو موجود نحدثه
        for c in self._data[asset_id]["cves"]:
            if c["cve_id"] == cve_id:
                c["risk_score"] = risk_score
                c["risk_category"] = risk_category
                self._save()
                return

        # لو جديد
        self._data[asset_id]["cves"].append({
            "cve_id": cve_id,
            "risk_score": risk_score,
            "risk_category": risk_category
        })

        self._save()