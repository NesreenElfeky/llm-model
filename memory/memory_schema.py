from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class CVEMemoryRecord:
    cve_id: str
    asset_id: str
    risk_score: float
    risk_category: str


@dataclass
class TargetMemory:
    asset_id: str
    cves: List[CVEMemoryRecord]


def to_dict(memory: TargetMemory) -> dict:
    return asdict(memory)