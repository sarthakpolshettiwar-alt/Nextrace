import sys
import os
import unittest
from datetime import datetime

from usbstor_parser import UsbDevice
from tools.session_repository import UsbSession, UsbSubEvent
from tools.session_correlator import UsbSessionCorrelator, extract_vid_pid, format_duration
from tools.analytics_service import UsbAnalyticsService
from tools.report_generator import generate_pdf_report

class TestUsbSessionEngine(unittest.TestCase):

    def test_vid_pid_extraction(self):
        text = r"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\VID_0781&PID_5567\4C530001330910119280"
        vid, pid = extract_vid_pid(text)
        self.assertEqual(vid, "0781")
        self.assertEqual(pid, "5567")

    def test_format_duration(self):
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(2932), "48m 52s")
        self.assertEqual(format_duration(11830), "3h 17m 10s")

    def test_session_hash_and_serialization(self):
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
            connection_type="USBSTOR",
            sub_events=[
                UsbSubEvent(timestamp="2026-07-21 09:51:23 IST", event_id="400", event_name="Connected"),
                UsbSubEvent(timestamp="2026-07-21 10:40:15 IST", event_id="1010", event_name="Disconnected")
            ]
        )
        
        self.assertTrue(len(sess.session_hash) == 64)
        serialized = sess.to_dict()
        self.assertEqual(serialized['session_id'], "USB-SESS-001")
        self.assertEqual(len(serialized['sub_events']), 2)
        
        reconstructed = UsbSession.from_dict(serialized)
        self.assertEqual(reconstructed.session_id, "USB-SESS-001")
        self.assertEqual(reconstructed.session_hash, sess.session_hash)

    def test_session_correlation(self):
        dev = UsbDevice(
            vendor="SanDisk",
            product="Cruzer Blade",
            revision="1.00",
            serial_number="4C530001330910119280",
            friendly_name="SanDisk Cruzer Blade USB Device",
            parent_id_prefix=None,
            last_write_time=datetime(2026, 7, 21, 9, 51, 23)
        )
        
        events = [
            {
                'timestamp': '2026-07-21 09:51:23 IST',
                'event_id': '400',
                'device_path': r'USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\VID_0781&PID_5567\4C530001330910119280',
                'serial_number': '4C530001330910119280'
            },
            {
                'timestamp': '2026-07-21 09:51:25 IST',
                'event_id': '410',
                'device_path': r'USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\VID_0781&PID_5567\4C530001330910119280',
                'serial_number': '4C530001330910119280'
            },
            {
                'timestamp': '2026-07-21 10:40:15 IST',
                'event_id': '1010',
                'device_path': r'USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\VID_0781&PID_5567\4C530001330910119280',
                'serial_number': '4C530001330910119280'
            }
        ]
        
        correlator = UsbSessionCorrelator()
        sessions = correlator.correlate([dev], events)
        
        self.assertEqual(len(sessions), 1)
        sess = sessions[0]
        self.assertEqual(sess.status, "Completed")
        self.assertEqual(sess.duration_formatted, "48m 52s")
        self.assertEqual(sess.vid, "0781")
        self.assertEqual(sess.pid, "5567")
        self.assertEqual(len(sess.sub_events), 3)

    def test_analytics_service(self):
        sess1 = UsbSession(
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
            status="Completed"
        )
        sess2 = UsbSession(
            session_id="USB-SESS-002",
            device_name="Kingston DataTraveler",
            vendor="Kingston",
            product="DataTraveler",
            serial_number="00187D0F5E92",
            vid="0951",
            pid="1666",
            first_seen="2026-07-21 11:00:00 IST",
            last_seen="2026-07-21 11:15:00 IST",
            connected_timestamp="2026-07-21 11:00:00 IST",
            disconnected_timestamp=None,
            duration_seconds=0,
            duration_formatted="Active",
            status="Disconnected"

        )
        
        dev1 = UsbDevice("SanDisk", "Cruzer", "1.0", "4C530001330910119280", "SanDisk Cruzer", None, None)
        dev2 = UsbDevice("Kingston", "DataTraveler", "1.0", "00187D0F5E92", "Kingston DT", None, None)

        analytics = UsbAnalyticsService.calculate_analytics([sess1, sess2], [dev1, dev2])
        self.assertEqual(analytics['total_sessions'], 2)
        self.assertEqual(analytics['completed_sessions'], 1)
        self.assertEqual(analytics['unexpected_removals'], 1)
        self.assertEqual(analytics['average_duration_formatted'], "48m 52s")

    def test_pdf_report_generation(self):
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
            status="Completed"
        )
        dev = UsbDevice("SanDisk", "Cruzer", "1.0", "4C530001330910119280", "SanDisk Cruzer", None, None)
        analytics = UsbAnalyticsService.calculate_analytics([sess], [dev])
        
        results = {
            'devices': [dev],
            'risks': [],
            'events': [],
            'sessions': [sess],
            'analytics': analytics
        }
        
        pdf_out = os.path.join("temp_samples", "test_session_report.pdf")
        generate_pdf_report(results, pdf_out)
        self.assertTrue(os.path.exists(pdf_out))
        self.assertGreater(os.path.getsize(pdf_out), 1000)

if __name__ == '__main__':
    unittest.main()
