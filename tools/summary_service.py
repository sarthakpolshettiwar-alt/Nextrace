from datetime import datetime
from typing import Dict, Any, List

class InvestigationSummaryService:
    @staticmethod
    def generate_summary(analytics: Dict[str, Any], sessions: List[Any], devices: List[Any]) -> Dict[str, Any]:
        total_devices = analytics.get('total_devices', len(devices))
        total_sessions = analytics.get('total_sessions', len(sessions))
        active_sessions = analytics.get('active_sessions', 0)
        unexpected_removals = analytics.get('unexpected_removals', 0)
        
        first_act = analytics.get('first_activity', 'N/A')
        last_act = analytics.get('last_activity', 'N/A')


        # Calculate Period and Day Count
        period_str = "N/A"
        day_count_str = ""
        
        dt_first = None
        dt_last = None
        
        if first_act != 'N/A' and last_act != 'N/A':
            try:
                clean_first = first_act.replace(' IST', '').replace('Z', '').strip()
                clean_last = last_act.replace(' IST', '').replace('Z', '').strip()
                if '+' in clean_first: clean_first = clean_first.split('+')[0]
                if '+' in clean_last: clean_last = clean_last.split('+')[0]
                
                dt_first = datetime.strptime(clean_first, '%Y-%m-%d %H:%M:%S')
                dt_last = datetime.strptime(clean_last, '%Y-%m-%d %H:%M:%S')
                
                start_fmt = dt_first.strftime('%d %b %Y')
                end_fmt = dt_last.strftime('%d %b %Y')
                
                days = (dt_last.date() - dt_first.date()).days
                if days == 0:
                    days = 1
                
                period_str = f"{start_fmt} → {end_fmt}" if start_fmt != end_fmt else start_fmt
                day_count_str = f"({days} Day{'s' if days != 1 else ''})"
            except Exception:
                period_str = f"{first_act[:10]} → {last_act[:10]}"

        # Case Status Badge
        if unexpected_removals > 0:
            badge = "Investigation Required"
        elif total_sessions > 15:
            badge = "Frequent USB Usage"
        elif total_devices >= 5:
            badge = "Multiple USB Devices Detected"
        else:
            badge = "Normal Activity"

        # Executive Case Summary Paragraph
        active_clause = f"{active_sessions} active USB device{' is' if active_sessions == 1 else 's are'} currently connected." if active_sessions > 0 else "No active USB device is currently connected."
        latest_clause = f"Latest activity occurred on {dt_last.strftime('%d %b %Y') if dt_last else last_act}." if last_act != 'N/A' else ""

        summary_paragraph = f"{total_sessions} USB sessions detected across {total_devices} unique device{'s' if total_devices != 1 else ''}. {latest_clause} {active_clause}".strip()

        return {
            'total_devices': total_devices,
            'total_sessions': total_sessions,
            'first_activity': first_act,
            'last_activity': last_act,
            'investigation_period': period_str,
            'day_count': day_count_str,
            'case_status_badge': badge,
            'case_summary_text': summary_paragraph
        }
