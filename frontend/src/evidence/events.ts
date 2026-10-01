import type { EventSnapshot, SecurityEvent } from '../types';

export interface PreservedEvidence {
  event_snapshot: SecurityEvent;
  event_snapshots?: EventSnapshot[];
  event_sha256?: string;
}

export function evidenceEvents(proof: PreservedEvidence): EventSnapshot[] {
  return proof.event_snapshots?.length
    ? proof.event_snapshots
    : [
        {
          event_id: proof.event_snapshot.event_id,
          event_sha256: proof.event_sha256 ?? '',
          event_snapshot: proof.event_snapshot,
        },
      ];
}
