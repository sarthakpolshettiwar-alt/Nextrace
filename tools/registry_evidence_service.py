import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
from usbstor_parser import UsbDevice, parse_usbstor_output

@dataclass
class MountedDriveArtifact:
    drive_letter: Optional[str]
    volume_guid: Optional[str]
    raw_signature: str
    serial_number_match: Optional[str]
    last_write_time: Optional[datetime]

class RegistryEvidenceService:
    def __init__(self):
        pass

    def parse_usbstor_devices(self, usbstor_raw_output: str) -> List[UsbDevice]:
        if not usbstor_raw_output:
            return []
        return parse_usbstor_output(usbstor_raw_output)

    def parse_mounted_devices(self, mountdev_raw_output: str) -> List[MountedDriveArtifact]:
        """
        Parses RegRipper mountdev2 / mountdev plugin output to extract drive letters and volume GUIDs.
        RegRipper mountdev output typically contains lines like:
        \DosDevices\E: -> {53f56307-b6bf-11d0-94f2-00a0c91efb8b} / Disk signature or Serial Number
        """
        artifacts: List[MountedDriveArtifact] = []
        if not mountdev_raw_output:
            return artifacts

        current_drive: Optional[str] = None
        current_guid: Optional[str] = None

        for line in mountdev_raw_output.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            # Match \DosDevices\E: or \??\Volume{...}
            dos_match = re.search(r'\\DosDevices\\([A-Z]:)', line_str, re.IGNORECASE)
            vol_match = re.search(r'\\Volume\{([0-9a-fA-F\-]{36})\}', line_str, re.IGNORECASE)
            
            drive_letter = dos_match.group(1).upper() if dos_match else None
            vol_guid = vol_match.group(1) if vol_match else None

            # Look for serial numbers or hex strings inside raw_signature
            sn_match = re.search(r'[\&\\]([0-9a-zA-Z]{8,32})', line_str)
            sn = sn_match.group(1) if sn_match else None

            if drive_letter or vol_guid:
                artifacts.append(MountedDriveArtifact(
                    drive_letter=drive_letter,
                    volume_guid=vol_guid,
                    raw_signature=line_str,
                    serial_number_match=sn,
                    last_write_time=None
                ))

        return artifacts

    def match_mounted_volume(self, serial_number: str, mounted_artifacts: List[MountedDriveArtifact]) -> Dict[str, Optional[str]]:
        result = {'drive_letter': None, 'volume_guid': None, 'registry_path': r'HKLM\SYSTEM\MountedDevices'}
        if not serial_number or not mounted_artifacts:
            return result

        clean_sn = serial_number.replace('&0', '').replace('&1', '').lower()

        for art in mounted_artifacts:
            sig_lower = art.raw_signature.lower()
            if clean_sn in sig_lower or (art.serial_number_match and art.serial_number_match.lower() in clean_sn):
                if art.drive_letter:
                    result['drive_letter'] = art.drive_letter
                if art.volume_guid:
                    result['volume_guid'] = art.volume_guid

        return result
