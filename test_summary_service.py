import unittest
from tools.summary_service import InvestigationSummaryService

class TestSummaryService(unittest.TestCase):

    def test_summary_generation(self):
        analytics = {
            'total_devices': 5,
            'total_sessions': 17,
            'active_sessions': 0,
            'unexpected_removals': 0,
            'first_activity': '2026-07-09 09:51:23 IST',
            'last_activity': '2026-07-21 10:40:15 IST'
        }
        
        sessions = [1] * 17
        devices = [1] * 5

        summary = InvestigationSummaryService.generate_summary(analytics, sessions, devices)
        
        self.assertEqual(summary['total_devices'], 5)
        self.assertEqual(summary['total_sessions'], 17)

        self.assertEqual(summary['investigation_period'], "09 Jul 2026 → 21 Jul 2026")
        self.assertEqual(summary['day_count'], "(12 Days)")
        self.assertEqual(summary['case_status_badge'], "Frequent USB Usage")
        self.assertIn("17 USB sessions detected across 5 unique devices", summary['case_summary_text'])

    def test_summary_single_day(self):
        analytics = {
            'total_devices': 1,
            'total_sessions': 2,
            'active_sessions': 1,
            'unexpected_removals': 1,
            'first_activity': '2026-07-23 08:00:00 IST',
            'last_activity': '2026-07-23 12:00:00 IST'
        }

        summary = InvestigationSummaryService.generate_summary(analytics, [1, 2], [1])
        self.assertEqual(summary['case_status_badge'], "Investigation Required")
        self.assertEqual(summary['day_count'], "(1 Day)")
        self.assertIn("1 active USB device is currently connected", summary['case_summary_text'])

if __name__ == '__main__':
    unittest.main()
