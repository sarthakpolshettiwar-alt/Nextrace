import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class UsbDevice:
    vendor: str
    product: str
    revision: str
    serial_number: str
    friendly_name: Optional[str]
    parent_id_prefix: Optional[str]
    last_write_time: Optional[datetime]

def parse_usbstor_output(raw_output: str) -> List[UsbDevice]:
    devices = []
    
    # Regex patterns
    # Matches lines like: Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
    device_header_pattern = re.compile(r'^\s*Disk&Ven_(.+?)&Prod_(.+?)&Rev_(.+?)\s*$', re.IGNORECASE)
    
    # Block variables
    current_device = None
    
    for line in raw_output.splitlines():
        # Check for new device header
        header_match = device_header_pattern.match(line)
        if header_match:
            # If we were parsing a device, save it
            if current_device and current_device.get('serial_number'):
                devices.append(_create_device(current_device))
                
            current_device = {
                'vendor': header_match.group(1).strip(),
                'product': header_match.group(2).strip(),
                'revision': header_match.group(3).strip(),
                'serial_number': None,
                'friendly_name': None,
                'parent_id_prefix': None,
                'last_write_time': None
            }
            continue
            
        if not current_device:
            continue
            
        # Parse fields within a device block
        line_stripped = line.strip()
        
        if line_stripped.startswith("S/N:"):
            sn_raw = line_stripped[4:].strip()
            
            # Check for timestamp in brackets (e.g. [2026-04-15 13:46:43Z])
            ts_match = re.search(r'\[(.*?)\]', sn_raw)
            if ts_match:
                ts_str = ts_match.group(1)
                try:
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%SZ")
                    current_device['last_write_time'] = dt
                except ValueError:
                    pass
                # Remove the timestamp part from the sn_raw
                sn_raw = sn_raw.replace(f'[{ts_str}]', '').strip()

            # Strip trailing "&0" if present
            if sn_raw.endswith("&0"):
                sn_raw = sn_raw[:-2]
            current_device['serial_number'] = sn_raw
            
        elif line_stripped.startswith("FriendlyName"):
            val = line_stripped.split(":", 1)[1].strip()
            current_device['friendly_name'] = val
            
        elif line_stripped.startswith("ParentIdPrefix"):
            val = line_stripped.split(":", 1)[1].strip()
            current_device['parent_id_prefix'] = val
            
        elif line_stripped.startswith("Last Write Time"):
            val = line_stripped.split(":", 1)[1].strip()
            # Parse datetime, format: Mon May  4 12:30:15 2020 Z
            try:
                # Remove extra spaces for day matching (e.g., 'May  4' -> 'May 4')
                val = re.sub(r'\s+', ' ', val)
                dt = datetime.strptime(val, "%a %b %d %H:%M:%S %Y Z")
                current_device['last_write_time'] = dt
            except ValueError:
                current_device['last_write_time'] = None

    # Don't forget the last device
    if current_device and current_device.get('serial_number'):
        devices.append(_create_device(current_device))
        
    return devices

def _create_device(data: dict) -> UsbDevice:
    return UsbDevice(
        vendor=data['vendor'],
        product=data['product'],
        revision=data['revision'],
        serial_number=data['serial_number'],
        friendly_name=data['friendly_name'],
        parent_id_prefix=data['parent_id_prefix'],
        last_write_time=data['last_write_time']
    )
