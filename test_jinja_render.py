import unittest
import os
from jinja2 import Environment, FileSystemLoader

class TestJinjaTemplateRender(unittest.TestCase):

    def test_usb_forensic_template_rendering(self):
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('usb_forensic.html')
        
        # Mock results data structure
        mock_results = {
            'analytics': {
                'total_devices': 5,
                'total_sessions': 17,
                'completed_sessions': 15,
                'unexpected_removals': 1,
                'active_sessions': 1,
                'longest_session': {'duration_formatted': '3h 17m', 'device_name': 'SanDisk'},
                'average_duration_formatted': '41m',
                'total_connected_time_formatted': '12h 30m',
                'first_activity': '2026-07-09 09:51:23 IST',
                'last_activity': '2026-07-21 10:40:15 IST'
            },
            'summary': {
                'total_devices': 5,
                'total_sessions': 17,
                'connection_status': 'All Disconnected',
                'connection_status_color': 'gray',
                'first_activity': '2026-07-09 09:51:23 IST',
                'last_activity': '2026-07-21 10:40:15 IST',
                'investigation_period': '09 Jul 2026 → 21 Jul 2026',
                'day_count': '(12 Days)',
                'case_status_badge': 'Frequent USB Usage',
                'case_summary_text': '17 USB sessions detected across 5 unique devices.'
            },
            'sessions': [
                {
                    'session_id': 'USB-SESS-001',
                    'device_name': 'SanDisk Cruzer Blade',
                    'vendor': 'SanDisk',
                    'product': 'Cruzer Blade',
                    'serial_number': '4C530001330910119280',
                    'vid': '0781',
                    'pid': '5567',
                    'first_seen': '2026-07-21 09:51:23 IST',
                    'last_seen': '2026-07-21 10:40:15 IST',
                    'connected_timestamp': '2026-07-21 09:51:23 IST',
                    'disconnected_timestamp': '2026-07-21 10:40:15 IST',
                    'duration_seconds': 2932,
                    'duration_formatted': '48m 52s',
                    'status': 'Completed',
                    'connection_type': 'USBSTOR',
                    'drive_letter': 'E:',
                    'volume_guid': '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}',
                    'registry_source': 'SYSTEM Hive',
                    'event_log_source': 'Kernel-PnP EVTX',
                    'session_hash': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
                    'sub_events': [],
                    'correlated_stages': [
                        {
                            'stage_name': 'USB Connected',
                            'timestamp': '2026-07-21 09:51:23 IST',
                            'status': 'Completed',
                            'icon_type': 'check',
                            'confidence_score': 95,
                            'confidence_level': 'High',
                            'confidence_reason': 'Multi-Source Evidence',
                            'evidence_sources': ['Windows Event Log', 'SYSTEM Registry'],
                            'event_id': '400',
                            'registry_path': r'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR',
                            'drive_letter': 'E:',
                            'volume_guid': '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}',
                            'artifact_details': 'Event ID 400 matched'
                        }
                    ],
                    'to_dict': lambda: {}
                }
            ],
            'devices': [],
            'risks': [],
            'events': []
        }

        # Render template with mock functions url_for, csrf_token, request, and current_user
        rendered = template.render(
            results=mock_results,
            hive_name='test_hive',
            url_for=lambda endpoint, **kwargs: f"/{endpoint}",
            csrf_token=lambda: "mock_csrf",
            request=type('Request', (), {'endpoint': 'usb_forensic'})(),
            current_user=type('User', (), {'profile_picture': None, 'name': 'Test User', 'username': 'Admin', 'email': 'test@example.com'})(),
            get_flashed_messages=lambda **kwargs: []
        )
        self.assertIn("USB Forensic Analysis", rendered)
        self.assertIn("USB Investigation Summary", rendered)
        self.assertIn("USB-SESS-001", rendered)


if __name__ == '__main__':
    unittest.main()
