import os
import xml.etree.ElementTree as ET
from datetime import datetime
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
except ImportError:
    pass

def parse_usb_events(evtx_path):
    """
    Parses a Windows Event Log (.evtx) looking for USB connection events.
    Returns a list of dicts: [{'timestamp': '...', 'event_id': '...', 'device_path': '...', 'serial_number': '...'}]
    """
    events = []
    if not os.path.exists(evtx_path):
        return events
        
    try:
        with Evtx(evtx_path) as log:
            for xml_str, record in evtx_file_xml_view(log.get_file_header()):
                # Parse the XML record
                try:
                    # Remove the xml declaration if present for ET
                    if xml_str.startswith("<?xml"):
                        xml_str = xml_str.split("?>", 1)[1]
                        
                    root = ET.fromstring(xml_str)
                    
                    # Evtx XML uses a namespace
                    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    
                    system = root.find("ns:System", ns)
                    if system is None:
                        continue
                        
                    event_id_elem = system.find("ns:EventID", ns)
                    if event_id_elem is None:
                        continue
                        
                    event_id = event_id_elem.text
                    
                    # Target Event IDs: 2003, 2100, 2102 (from DriverFrameworks-UserMode)
                    # Or 400 (Kernel-PnP)
                    if event_id in ['2003', '2100', '2102', '400', '1003']:
                        time_created = system.find("ns:TimeCreated", ns)
                        timestamp = time_created.attrib.get("SystemTime") if time_created is not None else "Unknown"
                        
                        # Try to extract the instance path/device ID from EventData or UserData
                        device_path = ""
                        user_data = root.find("ns:UserData", ns)
                        event_data = root.find("ns:EventData", ns)
                        
                        if user_data is not None:
                            # Search all text inside UserData
                            for elem in user_data.iter():
                                if elem.text and "USBSTOR" in elem.text.upper():
                                    device_path = elem.text
                                    break
                        
                        if not device_path and event_data is not None:
                            for data in event_data.findall("ns:Data", ns):
                                if data.text and "USBSTOR" in data.text.upper():
                                    device_path = data.text
                                    break
                                    
                        # Also check if it's just a regular USB string
                        if not device_path and user_data is not None:
                             for elem in user_data.iter():
                                if elem.text and "USB\\" in elem.text.upper():
                                    device_path = elem.text
                                    break
                        
                        # Extract serial number from device path if possible
                        # Typical format: USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001330910119280&0
                        serial_number = ""
                        if device_path:
                            parts = device_path.split('\\')
                            if len(parts) >= 3:
                                sn_raw = parts[-1]
                                # Remove the &0 suffix if present
                                if sn_raw.endswith("&0") or sn_raw.endswith("&1"):
                                    serial_number = sn_raw[:-2]
                                else:
                                    serial_number = sn_raw
                        
                        if timestamp != "Unknown":
                            # Parse ISO format and format clearly
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                            except ValueError:
                                pass
                                
                        events.append({
                            'timestamp': timestamp,
                            'event_id': event_id,
                            'device_path': device_path,
                            'serial_number': serial_number
                        })
                except ET.ParseError:
                    continue
    except Exception as e:
        print(f"Error parsing EVTX: {e}")
        
    return events

def correlate_events_with_devices(events, devices):
    """
    Matches parsed EVTX events with the USB devices found in the registry hive.
    Matches primarily by serial number.
    """
    correlated = []
    for event in events:
        if not event['serial_number'] and not event['device_path']:
            continue
            
        matched_device = None
        for dev in devices:
            if dev.serial_number and dev.serial_number in event['serial_number']:
                matched_device = dev
                break
            # Fallback: check if device vendor/product is in the device path
            if not matched_device and dev.vendor and dev.vendor in event['device_path']:
                matched_device = dev
                break
                
        if matched_device:
            correlated.append({
                'timestamp': event['timestamp'],
                'event_id': event['event_id'],
                'matched_device': matched_device.friendly_name or f"{matched_device.vendor} {matched_device.product}",
                'serial_number': matched_device.serial_number
            })
            
    # Remove duplicates
    unique_correlated = []
    seen = set()
    for c in correlated:
        key = f"{c['timestamp']}-{c['event_id']}-{c['serial_number']}"
        if key not in seen:
            seen.add(key)
            unique_correlated.append(c)
            
    # Sort by timestamp
    return sorted(unique_correlated, key=lambda x: x['timestamp'], reverse=True)

def analyze_risk(devices):
    """
    Applies rule-based risk analysis to devices.
    Flags:
    - Unusual Hours (Outside 9AM - 6PM)
    """
    risks = []
    for dev in devices:
        if not dev.last_write_time:
            continue
            
        hour = dev.last_write_time.hour
        is_weekend = dev.last_write_time.weekday() >= 5
        
        # Rule 1: Outside business hours (before 9am or after 6pm)
        if hour < 9 or hour >= 18 or is_weekend:
            day_type = "weekend" if is_weekend else "unusual hour"
            risks.append({
                'device_name': dev.friendly_name or f"{dev.vendor} {dev.product}",
                'serial_number': dev.serial_number,
                'reason': f"Device connected during {day_type} ({dev.last_write_time.strftime('%H:%M')} UTC)",
                'level': 'Medium'
            })
            
    return risks
