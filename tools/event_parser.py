import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import json
import time
import re

try:
    from evtx import PyEvtxParser
except ImportError:
    pass

def parse_usb_events(evtx_path, upload_id=None):
    """
    Parses a Windows Event Log (.evtx) looking for USB connection events.
    Returns a list of dicts: [{'timestamp': '...', 'event_id': '...', 'device_path': '...', 'serial_number': '...'}]
    """
    events = []
    if not os.path.exists(evtx_path):
        return events
        
    start_time = time.time()
    count = 0
    TIMEOUT = 90
    
    scan_time = 0.0
    parse_time = 0.0
    matched_count = 0
    
    def update_progress(msg):
        print(msg)
        if upload_id:
            prog_file = os.path.join('temp_samples', f'{upload_id}_progress.json')
            try:
                with open(prog_file, 'w') as f:
                    json.dump({'status': msg}, f)
            except Exception as e:
                pass

    try:
        parser = PyEvtxParser(evtx_path)
        for record in parser.records():
            count += 1
            
            if count % 1000 == 0:
                update_progress(f"Scanning event {count}...")
                
            if time.time() - start_time > TIMEOUT:
                raise TimeoutError("Event log processing took too long - try a smaller or filtered log")
                
            t0 = time.time()
            xml_str = record['data']
            
            # Early filter to avoid parsing irrelevant events
            target_ids = ['400', '410', '420', '430', '1010']
            # Fast plain string check for the Event ID in the XML
            if not any(f">{eid}<" in xml_str for eid in target_ids):
                scan_time += (time.time() - t0)
                continue
                
            scan_time += (time.time() - t0)
            
            matched_count += 1
            t1 = time.time()
            
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
                    parse_time += (time.time() - t1)
                    continue
                    
                event_id_elem = system.find("ns:EventID", ns)
                if event_id_elem is None:
                    parse_time += (time.time() - t1)
                    continue
                    
                event_id = event_id_elem.text
                
                # Target Event IDs: 2003, 2100, 2102 (from DriverFrameworks-UserMode)
                # Or 400 (Kernel-PnP)
                if event_id in target_ids:
                    time_created = system.find("ns:TimeCreated", ns)
                    timestamp = time_created.attrib.get("SystemTime") if time_created is not None else "Unknown"
                    
                    # Try to extract the instance path/device ID from EventData or UserData
                    device_path = ""
                    user_data = root.find("ns:UserData", ns)
                    event_data = root.find("ns:EventData", ns)
                    
                    if user_data is not None:
                        # Search all text inside UserData
                        for elem in user_data.iter():
                            if elem.text and ("VEN_" in elem.text.upper() or "PROD_" in elem.text.upper() or "USB" in elem.text.upper()):
                                device_path = elem.text
                                break
                    
                    if not device_path and event_data is not None:
                        for data in event_data.findall("ns:Data", ns):
                            if data.text and ("VEN_" in data.text.upper() or "PROD_" in data.text.upper() or "USB" in data.text.upper()):
                                device_path = data.text
                                break
                    
                    # Extract serial number from device path if possible
                    # Typical format: USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001330910119280&0
                    # For 1010 events, it might contain a GUID: {53f56307-b6bf-11d0-94f2-00a0c91efb8b}
                    serial_number = ""
                    if device_path:
                        guid_match = re.search(r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}', device_path)
                        if guid_match:
                            serial_number = guid_match.group(0)
                        else:
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
                            dt_ist = dt + timedelta(hours=5, minutes=30)
                            timestamp = dt_ist.strftime('%Y-%m-%d %H:%M:%S IST')
                        except ValueError:
                            pass
                            
                    print(f"[DEBUG] Matched Event ID {event_id} at {timestamp} | SN: '{serial_number}' | Path: '{device_path}'")
                            
                    events.append({
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'device_path': device_path,
                        'serial_number': serial_number
                    })
            except ET.ParseError:
                pass
            finally:
                parse_time += (time.time() - t1)
                
    except TimeoutError as e:
        print(str(e))
        raise
    except Exception as e:
        print(f"Error parsing EVTX: {e}")
        
    total_time = time.time() - start_time
    print(f"EVTX Parsing Complete.")
    print(f"Total Records Scanned: {count}")
    print(f"Records Matched for XML Parsing: {matched_count}")
    print(f"Time spent in pre-filter scan: {scan_time:.3f} seconds")
    print(f"Time spent in XML parsing: {parse_time:.3f} seconds")
    print(f"Total processing time: {total_time:.3f} seconds")
    
    config_count = sum(1 for e in events if e['event_id'] in ['400', '410', '420', '430'])
    mgmt_count = sum(1 for e in events if e['event_id'] == '1010')
    print(f"Parsed {config_count} Configuration events and {mgmt_count} Management events")
    
    return events

def correlate_events_with_devices(events, devices):
    """
    Matches parsed EVTX events with the USB devices found in the registry hive.
    Matches primarily by serial number.
    """
    print(f"[DEBUG] correlate_events_with_devices called with {len(events)} EVTX events and {len(devices)} registry devices.")
    for dev in devices:
        print(f"[DEBUG] Registry Device -> SN: '{dev.serial_number}', Vendor: '{dev.vendor}', Product: '{dev.product}'")
        
    correlated = []
    for event in events:
        if not event['serial_number'] and not event['device_path']:
            continue
            
        matched_device = None
        event_path_lower = (event['device_path'] or "").lower()
        
        for dev in devices:
            dev_vendor = (dev.vendor or "").lower()
            dev_product = (dev.product or "").lower()
            
            # 1. Exact Serial Number Match
            if dev.serial_number and event['serial_number'] and dev.serial_number in event['serial_number']:
                matched_device = dev
                break
                
            # 2. Fuzzy Substring Match on Vendor and Product
            if dev_vendor and dev_vendor in event_path_lower and dev_product and dev_product in event_path_lower:
                matched_device = dev
                break
                
            # 3. Fallback to just Vendor if Product is unknown
            if not matched_device and dev_vendor and dev_vendor in event_path_lower:
                matched_device = dev
                # Continue searching in case a better (vendor+product) match exists
                
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
            
    config_match = sum(1 for e in unique_correlated if e['event_id'] in ['400', '410', '420', '430'])
    mgmt_match = sum(1 for e in unique_correlated if e['event_id'] == '1010')
    print(f"[DEBUG] Matched {config_match} Configuration events and {mgmt_match} Management events")
            
    # Sort by timestamp
    return sorted(unique_correlated, key=lambda x: x['timestamp'], reverse=True)

def analyze_risk(devices, events=None):
    """
    Applies rule-based risk analysis to devices using both registry and event log data.
    """
    if events is None:
        events = []
        
    risks = []
    
    # Process events per device
    device_times = {}
    for dev in devices:
        if not dev.serial_number:
            continue
        if dev.serial_number not in device_times:
            device_times[dev.serial_number] = []
        if dev.last_write_time:
            # dev.last_write_time is UTC here. Convert to IST for comparison
            dt_ist = dev.last_write_time + timedelta(hours=5, minutes=30)
            device_times[dev.serial_number].append(dt_ist)
            
    for ev in events:
        sn = ev.get('serial_number')
        ts_str = ev.get('timestamp')
        if sn and ts_str:
            if sn not in device_times:
                device_times[sn] = []
            try:
                # ts_str format: 'YYYY-MM-DD HH:MM:SS IST'
                dt = datetime.strptime(ts_str.replace(' IST', ''), '%Y-%m-%d %H:%M:%S')
                device_times[sn].append(dt)
            except ValueError:
                pass
                
    # Determine the "hive capture time" (max timestamp across all devices)
    all_timestamps = []
    for times in device_times.values():
        all_timestamps.extend(times)
        
    hive_capture_time = max(all_timestamps) if all_timestamps else datetime.utcnow() + timedelta(hours=5, minutes=30)
    
    for dev in devices:
        sn = dev.serial_number
        if not sn:
            continue
            
        times = sorted(device_times.get(sn, []))
        if not times:
            continue
            
        device_name = dev.friendly_name or f"{dev.vendor} {dev.product}"
        
        # Rule: New/Unknown Device (First appearance within 24 hours of hive capture)
        earliest_time = times[0]
        if (hive_capture_time - earliest_time).total_seconds() <= 86400:
            risks.append({
                'device_name': device_name,
                'serial_number': sn,
                'reason': f"New/Unknown Device: First appearance is within 24h of capture ({earliest_time.strftime('%Y-%m-%d %H:%M:%S')} IST)",
                'level': 'Low'
            })
            
        # Check hours and rapid reconnection
        unusual_hour_flagged = False
        late_night_flagged = False
        
        for t in times:
            hour = t.hour
            is_weekend = t.weekday() >= 5
            
            # Late Night Activity: 12:00 AM - 5:00 AM
            if hour >= 0 and hour < 5:
                if not late_night_flagged:
                    risks.append({
                        'device_name': device_name,
                        'serial_number': sn,
                        'reason': f"Late Night Activity detected at {t.strftime('%Y-%m-%d %H:%M:%S')} IST",
                        'level': 'High'
                    })
                    late_night_flagged = True
            # Unusual Hours: Outside 9AM - 6PM
            elif hour < 9 or hour >= 18 or is_weekend:
                if not unusual_hour_flagged:
                    day_type = "weekend" if is_weekend else "unusual hour"
                    risks.append({
                        'device_name': device_name,
                        'serial_number': sn,
                        'reason': f"Unusual Hours: Device connected during {day_type} ({t.strftime('%Y-%m-%d %H:%M:%S')} IST)",
                        'level': 'Medium'
                    })
                    unusual_hour_flagged = True
                    
        # Rapid Reconnection: > 3 times within 10 minutes (meaning 4 events within 600s)
        if len(times) >= 4:
            for i in range(len(times) - 3):
                t1 = times[i]
                t4 = times[i+3]
                if (t4 - t1).total_seconds() <= 600:
                    risks.append({
                        'device_name': device_name,
                        'serial_number': sn,
                        'reason': f"Rapid Reconnection: 4+ events within 10 minutes starting at {t1.strftime('%Y-%m-%d %H:%M:%S')} IST",
                        'level': 'Medium'
                    })
                    break

    return risks
