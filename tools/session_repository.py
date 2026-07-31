import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class UsbSubEvent:
    timestamp: str
    event_id: str
    event_name: str
    device_path: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'event_id': self.event_id,
            'event_name': self.event_name,
            'device_path': self.device_path,
            'details': self.details
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UsbSubEvent':
        return cls(
            timestamp=data.get('timestamp', ''),
            event_id=str(data.get('event_id', '')),
            event_name=data.get('event_name', 'Event'),
            device_path=data.get('device_path'),
            details=data.get('details')
        )

@dataclass
class UsbSession:
    session_id: str
    device_name: str
    vendor: str
    product: str
    serial_number: str
    vid: str
    pid: str
    first_seen: Optional[str]
    last_seen: Optional[str]
    connected_timestamp: Optional[str]
    disconnected_timestamp: Optional[str]
    duration_seconds: int
    duration_formatted: str
    status: str  # Completed, Active, Unexpected Removal, Missing Disconnect Event, Incomplete Session, Corrupted Event Sequence, Unknown State
    connection_type: str = "USBSTOR"
    drive_letter: Optional[str] = None
    volume_guid: Optional[str] = None
    registry_source: str = "SYSTEM Hive"
    event_log_source: str = "Kernel-PnP EVTX"
    session_hash: str = ""
    sub_events: List[UsbSubEvent] = field(default_factory=list)

    def generate_hash(self) -> str:
        payload = f"{self.session_id}|{self.serial_number}|{self.vid}|{self.pid}|{self.connected_timestamp}|{self.disconnected_timestamp}|{self.status}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def __post_init__(self):
        if not self.session_hash:
            self.session_hash = self.generate_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'device_name': self.device_name,
            'vendor': self.vendor,
            'product': self.product,
            'serial_number': self.serial_number,
            'vid': self.vid,
            'pid': self.pid,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'connected_timestamp': self.connected_timestamp,
            'disconnected_timestamp': self.disconnected_timestamp,
            'duration_seconds': self.duration_seconds,
            'duration_formatted': self.duration_formatted,
            'status': self.status,
            'connection_type': self.connection_type,
            'drive_letter': self.drive_letter,
            'volume_guid': self.volume_guid,
            'registry_source': self.registry_source,
            'event_log_source': self.event_log_source,
            'session_hash': self.session_hash,
            'sub_events': [e.to_dict() if isinstance(e, UsbSubEvent) else e for e in self.sub_events]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UsbSession':
        sub_events_raw = data.get('sub_events', [])
        sub_events = [
            e if isinstance(e, UsbSubEvent) else UsbSubEvent.from_dict(e)
            for e in sub_events_raw
        ]
        return cls(
            session_id=data.get('session_id', f"USB-SESS-{uuid.uuid4().hex[:8]}"),
            device_name=data.get('device_name', 'Unknown USB Device'),
            vendor=data.get('vendor', 'Unknown'),
            product=data.get('product', 'Unknown'),
            serial_number=data.get('serial_number', 'N/A'),
            vid=data.get('vid', 'N/A'),
            pid=data.get('pid', 'N/A'),
            first_seen=data.get('first_seen'),
            last_seen=data.get('last_seen'),
            connected_timestamp=data.get('connected_timestamp'),
            disconnected_timestamp=data.get('disconnected_timestamp'),
            duration_seconds=data.get('duration_seconds', 0),
            duration_formatted=data.get('duration_formatted', 'N/A'),
            status=data.get('status', 'Unknown State'),
            connection_type=data.get('connection_type', 'USBSTOR'),
            drive_letter=data.get('drive_letter'),
            volume_guid=data.get('volume_guid'),
            registry_source=data.get('registry_source', 'SYSTEM Hive'),
            event_log_source=data.get('event_log_source', 'Kernel-PnP EVTX'),
            session_hash=data.get('session_hash', ''),
            sub_events=sub_events
        )
