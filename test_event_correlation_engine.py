import unittest
from datetime import datetime

from usbstor_parser import UsbDevice
from tools.session_repository import UsbSession, UsbSubEvent
from tools.registry_evidence_service import RegistryEvidenceService, MountedDriveArtifact
from tools.event_log_evidence_service import EventLogEvidenceService, ForensicsEventArtifact
from tools.evidence_resolver import EvidenceResolver
from tools.correlation_rules import CorrelationRules
from tools.event_correlation_service import EventCorrelationService

class TestEventCorrelationEngine(unittest.TestCase):

    def test_mounted_devices_parsing(self):
        sample_output = r"""
\DosDevices\E: -> \??\Volume{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
\DosDevices\F: -> USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade#4C530001330910119280&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
"""
        reg_service = RegistryEvidenceService()
        artifacts = reg_service.parse_mounted_devices(sample_output)
        self.assertEqual(len(artifacts), 2)
        
        match_result = reg_service.match_mounted_volume("4C530001330910119280", artifacts)
        self.assertEqual(match_result['drive_letter'], 'F:')

    def test_evidence_resolver_confidence(self):
        conf_high = EvidenceResolver.resolve(has_registry=True, has_event_log=True, serial_matched=True, stage_name="USB Connected")
        self.assertEqual(conf_high.level, "High")
        self.assertEqual(conf_high.score, 95)

        conf_med = EvidenceResolver.resolve(has_registry=True, has_event_log=False, serial_matched=True, stage_name="Volume Mounted")
        self.assertEqual(conf_med.level, "Medium")
        self.assertEqual(conf_med.score, 80)

        conf_none = EvidenceResolver.resolve(has_registry=False, has_event_log=False, serial_matched=False, stage_name="Explorer Access", is_missing=True)
        self.assertEqual(conf_none.level, "None")
        self.assertEqual(conf_none.score, 0)
        self.assertEqual(conf_none.reason, "Evidence Not Found in Uploaded Registry or Event Logs")

    def test_event_correlation_service_enrichment(self):
        sess = UsbSession(
            session_id="USB-SESS-001",
            device_name="SanDisk Cruzer Blade",
            vendor="SanDisk",
            product="Cruzer Blade",
            serial_number="4C530001330910119280",
            vid="0781",
            pid="5567",
            first_seen="2026-07-21 09:51:23 IST",
            last_seen="2026-07-21 10:40:15 IST",
            connected_timestamp="2026-07-21 09:51:23 IST",
            disconnected_timestamp="2026-07-21 10:40:15 IST",
            duration_seconds=2932,
            duration_formatted="48m 52s",
            status="Completed",
            sub_events=[
                UsbSubEvent(timestamp="2026-07-21 09:51:23 IST", event_id="400", event_name="Connected"),
                UsbSubEvent(timestamp="2026-07-21 10:40:15 IST", event_id="1010", event_name="Disconnected")
            ]
        )
        
        mounted_art = MountedDriveArtifact(
            drive_letter="E:",
            volume_guid="{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
            raw_signature=r"\DosDevices\E: -> USBSTOR#4C530001330910119280",
            serial_number_match="4C530001330910119280",
            last_write_time=None
        )
        
        service = EventCorrelationService()
        enriched = service.process_and_enrich_sessions([sess], [mounted_art])
        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0].drive_letter, "E:")

if __name__ == '__main__':
    unittest.main()
