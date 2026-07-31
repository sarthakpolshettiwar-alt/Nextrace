from typing import List, Dict, Any, Optional
from tools.registry_evidence_service import RegistryEvidenceService, MountedDriveArtifact
from tools.event_log_evidence_service import EventLogEvidenceService
from tools.correlation_rules import CorrelationRules

class EventCorrelationService:
    def __init__(self):
        self.registry_service = RegistryEvidenceService()
        self.event_service = EventLogEvidenceService()

    def process_and_enrich_sessions(
        self,
        sessions: List[Any],
        mounted_artifacts: Optional[List[MountedDriveArtifact]] = None
    ) -> List[Any]:
        if mounted_artifacts is None:
            mounted_artifacts = []

        for sess in sessions:
            sn = getattr(sess, 'serial_number', '') or ''
            
            # Match mounted volume info if available
            vol_match = self.registry_service.match_mounted_volume(sn, mounted_artifacts)
            if vol_match.get('drive_letter'):
                sess.drive_letter = vol_match['drive_letter']
            if vol_match.get('volume_guid'):
                sess.volume_guid = vol_match['volume_guid']

            # Extract sub_events from session
            sub_events = []
            raw_sub = getattr(sess, 'sub_events', [])
            for e in raw_sub:
                if hasattr(e, 'to_dict'):
                    sub_events.append(e.to_dict())
                elif isinstance(e, dict):
                    sub_events.append(e)

        return sessions
