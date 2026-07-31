from typing import List, Dict, Any, Optional

class CorrelationRules:
    @staticmethod
    def deduplicate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for ev in events:
            key = f"{ev.get('timestamp')}-{ev.get('event_id')}-{ev.get('serial_number')}-{ev.get('device_path')}"
            if key not in seen:
                seen.add(key)
                unique.append(ev)
        return unique

    @staticmethod
    def map_event_id_to_stage(event_id: str) -> str:
        mapping = {
            '400': 'Driver Install Start',
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
            '1010': 'USB Disconnected'
        }
        return mapping.get(str(event_id), f"Event ID {event_id}")
