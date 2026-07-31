import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
from tools.event_parser import parse_usb_events

@dataclass
class ForensicsEventArtifact:
    timestamp: str
    event_id: str
    channel: str
    stage_name: str
    serial_number: Optional[str]
    device_path: Optional[str]
    drive_letter: Optional[str]
    volume_guid: Optional[str]
    details: str

EVENT_STAGE_MAP = {
    '400': 'Driver Installation Started',
    '410': 'Driver Installed',
    '420': 'Device Configured',
    '430': 'Device Ready',
    '1001': 'Volume Mounted',
    '1002': 'Drive Letter Assigned',
    '2001': 'Disk Arrival',
    '2002': 'Disk Ejection',
    '2003': 'USB Connected',
    '2100': 'Device Eject Triggered',
    '2102': 'Safe Removal',
    '1010': 'USB Disconnected',
    '100': 'Explorer Access',
    '101': 'Explorer File Open'
}

class EventLogEvidenceService:
    def __init__(self):
        pass

    def extract_evidence_events(self, evtx_path: str, upload_id: Optional[str] = None) -> List[ForensicsEventArtifact]:
        parsed_raw = parse_usb_events(evtx_path, upload_id=upload_id)
        artifacts: List[ForensicsEventArtifact] = []

        for ev in parsed_raw:
            eid = str(ev.get('event_id', ''))
            ts = ev.get('timestamp', 'Unknown')
            dp = ev.get('device_path') or ''
            sn = ev.get('serial_number') or None

            # Extract drive letter or volume guid if present in path or XML string
            drive_match = re.search(r'([A-Z]:)', dp, re.IGNORECASE)
            guid_match = re.search(r'\{[0-9a-fA-F\-]{36}\}', dp)

            drive_letter = drive_match.group(1).upper() if drive_match else None
            vol_guid = guid_match.group(0) if guid_match else None

            stage_name = EVENT_STAGE_MAP.get(eid, f"Event ID {eid}")
            channel = "Microsoft-Windows-Kernel-PnP" if eid in ['400', '410', '420', '430', '1010'] else "Windows Event Log"

            artifacts.append(ForensicsEventArtifact(
                timestamp=ts,
                event_id=eid,
                channel=channel,
                stage_name=stage_name,
                serial_number=sn,
                device_path=dp,
                drive_letter=drive_letter,
                volume_guid=vol_guid,
                details=f"Record matched Event ID {eid} in {channel}"
            ))

        return artifacts
