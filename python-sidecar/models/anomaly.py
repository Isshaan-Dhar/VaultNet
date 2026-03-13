from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional
import json


@dataclass
class AnomalyAlert:
    alert_type: str
    severity: str
    username: str
    user_id: Optional[str]
    detail: str
    evidence: dict
    detected_at: str = None

    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = datetime.utcnow().isoformat() + "Z"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)