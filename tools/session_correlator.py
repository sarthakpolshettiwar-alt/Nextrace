import re
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from usbstor_parser import UsbDevice
from tools.session_repository import UsbSession, UsbSubEvent
from tools.event_correlation_service import EventCorrelationService

EVENT_NAMES = {
    '400': 'Connected (Driver Install Start)',
    '410': 'Driver Installed',
    '420': 'Device Configured',
    '430': 'Device Ready',
    '1010': 'Disconnected / Removed',
    '2003': 'UserMode Connected',
    '2100': 'UserMode Event',
    '2102': 'UserMode Eject'
}

def extract_vid_pid(text: str) -> tuple[str, str]:
    if not text:
        return ("N/A", "N/A")
    vid_match = re.search(r'VID_([0-9a-fA-F]{4})', text, re.IGNORECASE)
    pid_match = re.search(r'PID_([0-9a-fA-F]{4})', text, re.IGNORECASE)
    vid = vid_match.group(1).upper() if vid_match else "N/A"
    pid = pid_match.group(1).upper() if pid_match else "N/A"
    return (vid, pid)

def parse_timestamp_str(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str or ts_str == "Unknown":
        return None
    try:
        cleaned = ts_str.replace(' IST', '').replace('Z', '').strip()
        if '+' in cleaned:
            cleaned = cleaned.split('+')[0]
        return datetime.strptime(cleaned, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None

def format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "0s"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)

class UsbSessionCorrelator:
    def __init__(self, max_reconnect_gap_seconds: int = 300):
        self.max_reconnect_gap_seconds = max_reconnect_gap_seconds

    def correlate(self, devices: List[UsbDevice], events: List[Dict[str, Any]]) -> List[UsbSession]:
        sessions: List[UsbSession] = []
        
        # 1. Map devices by serial number and device name
        device_map: Dict[str, UsbDevice] = {}
        for dev in devices:
            if dev.serial_number:
                device_map[dev.serial_number] = dev

        # 2. Group events by serial number (or fallback key)
        grouped_events: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sn = ev.get('serial_number') or "UNKNOWN_SN"
            if sn not in grouped_events:
                grouped_events[sn] = []
            grouped_events[sn].append(ev)

        session_counter = 1

        # 3. Correlate per serial number / device
        processed_serials = set()

        for sn, ev_list in grouped_events.items():
            processed_serials.add(sn)
            matched_dev = device_map.get(sn)
            
            # Extract metadata
            device_name = "Unknown Device"
            vendor = "Unknown"
            product = "Unknown"
            vid, pid = "N/A", "N/A"
            
            if matched_dev:
                device_name = matched_dev.friendly_name or f"{matched_dev.vendor} {matched_dev.product}"
                vendor = matched_dev.vendor or "Unknown"
                product = matched_dev.product or "Unknown"

            # Always attempt extracting VID / PID from event paths
            for ev in ev_list:
                dp = ev.get('device_path') or ""
                v, p = extract_vid_pid(dp)
                if v != "N/A": vid = v
                if p != "N/A": pid = p
                if not matched_dev:
                    if "VEN_" in dp.upper():
                        v_match = re.search(r'VEN_([^\&]+)', dp, re.IGNORECASE)
                        if v_match: vendor = v_match.group(1).replace('_', ' ')
                    if "PROD_" in dp.upper():
                        p_match = re.search(r'PROD_([^\&]+)', dp, re.IGNORECASE)
                        if p_match: product = p_match.group(1).replace('_', ' ')

            if not matched_dev and (vendor != "Unknown" or product != "Unknown"):
                device_name = f"{vendor} {product}".strip()

            if matched_dev and (vid == "N/A" or pid == "N/A"):
                # Check parent_id_prefix or last_write_time
                pass

            # Sort events chronologically
            valid_events = []
            for ev in ev_list:
                dt = parse_timestamp_str(ev.get('timestamp'))
                if dt:
                    valid_events.append((dt, ev))
            
            valid_events.sort(key=lambda x: x[0])

            # Reconstruction loop
            current_session_events: List[tuple[datetime, Dict[str, Any]]] = []
            
            for dt, ev in valid_events:
                eid = str(ev.get('event_id', ''))
                
                if eid in ['400', '410', '420', '430', '2003']:
                    # Connection sequence event
                    if current_session_events:
                        first_dt = current_session_events[0][0]
                        last_dt = current_session_events[-1][0]
                        
                        # If there is already a disconnect event in current_session_events, close it
                        has_disconnect = any(str(e[1].get('event_id')) == '1010' for e in current_session_events)
                        if has_disconnect or (dt - last_dt).total_seconds() > self.max_reconnect_gap_seconds:
                            # Finalize previous session
                            sess = self._build_session(
                                session_id=f"USB-SESS-{session_counter:03d}",
                                device_name=device_name,
                                vendor=vendor,
                                product=product,
                                serial_number=sn,
                                vid=vid,
                                pid=pid,
                                events=current_session_events,
                                matched_dev=matched_dev
                            )
                            sessions.append(sess)
                            session_counter += 1
                            current_session_events = []

                    current_session_events.append((dt, ev))
                    
                elif eid == '1010':
                    # Disconnect event
                    current_session_events.append((dt, ev))
                    sess = self._build_session(
                        session_id=f"USB-SESS-{session_counter:03d}",
                        device_name=device_name,
                        vendor=vendor,
                        product=product,
                        serial_number=sn,
                        vid=vid,
                        pid=pid,
                        events=current_session_events,
                        matched_dev=matched_dev
                    )
                    sessions.append(sess)
                    session_counter += 1
                    current_session_events = []

            # Clean up remaining open session if any
            if current_session_events:
                sess = self._build_session(
                    session_id=f"USB-SESS-{session_counter:03d}",
                    device_name=device_name,
                    vendor=vendor,
                    product=product,
                    serial_number=sn,
                    vid=vid,
                    pid=pid,
                    events=current_session_events,
                    matched_dev=matched_dev
                )
                sessions.append(sess)
                session_counter += 1

        # 4. Handle Registry devices without event logs
        for dev in devices:
            sn = dev.serial_number
            if sn and sn not in processed_serials:
                dev_name = dev.friendly_name or f"{dev.vendor} {dev.product}"
                lw_time_str = dev.last_write_time.strftime('%Y-%m-%d %H:%M:%S IST') if dev.last_write_time else None
                
                sess = UsbSession(
                    session_id=f"USB-SESS-{session_counter:03d}",
                    device_name=dev_name,
                    vendor=dev.vendor or "Unknown",
                    product=dev.product or "Unknown",
                    serial_number=sn,
                    vid="N/A",
                    pid="N/A",
                    first_seen=lw_time_str,
                    last_seen=lw_time_str,
                    connected_timestamp=lw_time_str,
                    disconnected_timestamp=None,
                    duration_seconds=0,
                    duration_formatted="Missing Log Data",
                    status="Missing Disconnect Event",
                    connection_type="USBSTOR",
                    registry_source="SYSTEM Hive (RegRipper)",
                    event_log_source="No Event Log Matched",
                    sub_events=[
                        UsbSubEvent(
                            timestamp=lw_time_str or "Unknown",
                            event_id="REGISTRY",
                            event_name="Registry Last Write Timestamp",
                            details="Parsed from SYSTEM Registry Hive USBSTOR key"
                        )
                    ]
                )
                sessions.append(sess)
                session_counter += 1

        # Sort sessions by connected timestamp descending
        def get_sort_key(s: UsbSession):
            dt = parse_timestamp_str(s.connected_timestamp or s.first_seen)
            return dt or datetime.min

        sessions.sort(key=get_sort_key, reverse=True)

        # Enrich sessions with EventCorrelationService
        event_correlation_service = EventCorrelationService()
        sessions = event_correlation_service.process_and_enrich_sessions(sessions)

        return sessions

    def _build_session(
        self,
        session_id: str,
        device_name: str,
        vendor: str,
        product: str,
        serial_number: str,
        vid: str,
        pid: str,
        events: List[tuple[datetime, Dict[str, Any]]],
        matched_dev: Optional[UsbDevice]
    ) -> UsbSession:
        sub_events = []
        conn_dt: Optional[datetime] = None
        disconn_dt: Optional[datetime] = None
        has_connect_event = False
        has_disconnect_event = False

        for dt, ev in events:
            eid = str(ev.get('event_id', ''))
            ename = EVENT_NAMES.get(eid, f"Event {eid}")
            ts_str = ev.get('timestamp', dt.strftime('%Y-%m-%d %H:%M:%S IST'))
            
            if eid in ['400', '410', '420', '430', '2003']:
                has_connect_event = True
                if not conn_dt:
                    conn_dt = dt
            elif eid == '1010':
                has_disconnect_event = True
                disconn_dt = dt

            sub_events.append(UsbSubEvent(
                timestamp=ts_str,
                event_id=eid,
                event_name=ename,
                device_path=ev.get('device_path'),
                details=f"Event ID {eid} recorded"
            ))

        conn_str = conn_dt.strftime('%Y-%m-%d %H:%M:%S IST') if (has_connect_event and conn_dt) else None
        disconn_str = disconn_dt.strftime('%Y-%m-%d %H:%M:%S IST') if (has_disconnect_event and disconn_dt) else None
        first_seen_str = conn_str
        last_seen_str = disconn_str or (events[-1][1].get('timestamp') if events else None)

        duration_seconds = 0
        duration_formatted = "N/A"
        status = "Unknown State"

        if has_connect_event and has_disconnect_event and conn_dt and disconn_dt:
            if disconn_dt >= conn_dt:
                duration_seconds = int((disconn_dt - conn_dt).total_seconds())
                duration_formatted = format_duration(duration_seconds)
                status = "Completed"
            else:
                status = "Corrupted Event Sequence"
                duration_formatted = "Invalid Sequence"
        elif has_connect_event and not has_disconnect_event:
            duration_formatted = "Active / Incomplete"
            status = "Active" if (datetime.now() - conn_dt).total_seconds() < 86400 else "Missing Disconnect Event"
        elif not has_connect_event and has_disconnect_event:
            status = "Unexpected Removal"
            duration_formatted = "No Connect Event"

        return UsbSession(
            session_id=session_id,
            device_name=device_name,
            vendor=vendor,
            product=product,
            serial_number=serial_number,
            vid=vid,
            pid=pid,
            first_seen=first_seen_str,
            last_seen=last_seen_str,
            connected_timestamp=conn_str,
            disconnected_timestamp=disconn_str,
            duration_seconds=duration_seconds,
            duration_formatted=duration_formatted,
            status=status,
            connection_type="USBSTOR / Kernel-PnP",
            registry_source="SYSTEM Hive" if matched_dev else "Event Log Only",
            event_log_source="Kernel-PnP EVTX",
            sub_events=sub_events
        )
