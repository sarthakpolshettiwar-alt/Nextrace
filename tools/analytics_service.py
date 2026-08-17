from collections import Counter
from typing import List, Dict, Any, Optional
from usbstor_parser import UsbDevice
from tools.session_repository import UsbSession
from tools.session_correlator import format_duration, parse_timestamp_str

class UsbAnalyticsService:
    @staticmethod
    def calculate_analytics(sessions: List[UsbSession], devices: List[UsbDevice]) -> Dict[str, Any]:
        total_devices = len(devices) if devices else len(set(s.serial_number for s in sessions if s.serial_number != "N/A"))
        total_sessions = len(sessions)
        
        completed_sessions = sum(1 for s in sessions if s.status == "Completed")
        active_sessions = sum(1 for s in sessions if s.status == "Active")
        unexpected_removals = sum(1 for s in sessions if s.status in ("Unexpected Removal", "Disconnected"))

        missing_disconnects = sum(1 for s in sessions if s.status == "Missing Disconnect Event")

        # Durations
        completed_durations = [s.duration_seconds for s in sessions if s.status == "Completed" and s.duration_seconds > 0]
        
        avg_duration_sec = int(sum(completed_durations) / len(completed_durations)) if completed_durations else 0
        avg_duration_formatted = format_duration(avg_duration_sec) if avg_duration_sec > 0 else "N/A"

        total_connected_sec = sum(s.duration_seconds for s in sessions if s.duration_seconds > 0)
        total_connected_formatted = format_duration(total_connected_sec) if total_connected_sec > 0 else "N/A"

        # Longest & Shortest
        longest_session = None
        shortest_session = None
        
        if completed_durations:
            sorted_completed = sorted([s for s in sessions if s.status == "Completed" and s.duration_seconds > 0], key=lambda x: x.duration_seconds)
            shortest_session = {
                'session_id': sorted_completed[0].session_id,
                'device_name': sorted_completed[0].device_name,
                'duration_formatted': sorted_completed[0].duration_formatted,
                'duration_seconds': sorted_completed[0].duration_seconds
            }
            longest_session = {
                'session_id': sorted_completed[-1].session_id,
                'device_name': sorted_completed[-1].device_name,
                'duration_formatted': sorted_completed[-1].duration_formatted,
                'duration_seconds': sorted_completed[-1].duration_seconds
            }

        # First and Last Activity timestamps
        all_timestamps = []
        for s in sessions:
            for ts_attr in [s.connected_timestamp, s.disconnected_timestamp, s.first_seen, s.last_seen]:
                dt = parse_timestamp_str(ts_attr)
                if dt:
                    all_timestamps.append((dt, ts_attr))

        all_timestamps.sort(key=lambda x: x[0])
        first_activity = all_timestamps[0][1] if all_timestamps else "N/A"
        last_activity = all_timestamps[-1][1] if all_timestamps else "N/A"

        # Most Frequent Device and Vendor
        device_counts = Counter(s.device_name for s in sessions if s.device_name and s.device_name != "Unknown Device")
        vendor_counts = Counter(s.vendor for s in sessions if s.vendor and s.vendor != "Unknown")

        most_frequent_device = device_counts.most_common(1)[0][0] if device_counts else (devices[0].friendly_name if devices else "N/A")
        most_frequent_vendor = vendor_counts.most_common(1)[0][0] if vendor_counts else (devices[0].vendor if devices else "N/A")

        return {
            'total_devices': total_devices,
            'total_sessions': total_sessions,
            'completed_sessions': completed_sessions,
            'active_sessions': active_sessions,
            'unexpected_removals': unexpected_removals,
            'missing_disconnects': missing_disconnects,
            'average_duration_seconds': avg_duration_sec,
            'average_duration_formatted': avg_duration_formatted,
            'total_connected_time_seconds': total_connected_sec,
            'total_connected_time_formatted': total_connected_formatted,
            'longest_session': longest_session,
            'shortest_session': shortest_session,
            'first_activity': first_activity,
            'last_activity': last_activity,
            'most_frequent_device': most_frequent_device,
            'most_frequent_vendor': most_frequent_vendor
        }
