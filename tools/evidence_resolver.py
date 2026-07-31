from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class ResolvedConfidence:
    score: int  # 0 to 100
    level: str  # High, Medium, Low, None
    reason: str

class EvidenceResolver:
    @staticmethod
    def resolve(
        has_registry: bool,
        has_event_log: bool,
        serial_matched: bool,
        stage_name: str,
        is_missing: bool = False
    ) -> ResolvedConfidence:
        if is_missing:
            return ResolvedConfidence(
                score=0,
                level="None",
                reason="Evidence Not Found in Uploaded Registry or Event Logs"
            )

        if has_registry and has_event_log and serial_matched:
            return ResolvedConfidence(
                score=95,
                level="High",
                reason=f"Multi-Source Correlated Evidence (SYSTEM Registry + Event Log Serial Match)"
            )
        elif has_event_log and serial_matched:
            return ResolvedConfidence(
                score=90,
                level="High",
                reason=f"Direct Event Log Match with Verified Serial Number"
            )
        elif has_registry and not has_event_log:
            return ResolvedConfidence(
                score=80,
                level="Medium",
                reason=f"SYSTEM Registry Hive Key (USBSTOR / MountedDevices)"
            )
        elif has_event_log and not serial_matched:
            return ResolvedConfidence(
                score=70,
                level="Medium",
                reason=f"Event Log Record matched via Vendor/Product String Proximity"
            )
        else:
            return ResolvedConfidence(
                score=50,
                level="Low",
                reason=f"Inferred Lifecycle Stage based on timestamp sequence"
            )
