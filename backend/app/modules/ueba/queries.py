"""One atomic PostgreSQL snapshot with proof bounds before JSON materialization.

Append-only membership is the trusted index boundary. Source-wide receipt metadata
detects pending indexing and count/hash inconsistencies; full original and identity
proofs cover linked events. Absence cannot be proved against a privileged owner who
disables storage guards and rewrites a coherent membership index. Such an attack
requires rebuilding or independently auditing that index, not a healthy GET result.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.modules.ueba.schemas import UebaFilters

MAX_EVENTS = 2000
MAX_BYTES = 8 * 1024 * 1024

_REPORT = text("""
WITH identity AS MATERIALIZED (
 SELECT * FROM public.entity_identities WHERE id=CAST(:entity AS uuid) AND mode=:mode
 AND (:mode='live' OR (dataset_id=CAST(:dataset AS uuid) AND run_id=CAST(:run AS uuid)))
), scoped AS MATERIALIZED (
 SELECT n.event_id,n.document_sha256,p.document_sha256 AS receipt_hash,p.identity_policy,
 p.observation_count,p.event_id AS indexed_id
 FROM public.normalized_events n JOIN public.raw_events r ON r.id=n.event_id
 JOIN identity i ON r.source_id=i.source_id AND i.kind IN ('host','user')
 LEFT JOIN public.entity_index_receipts p ON p.event_id=n.event_id
 WHERE n.timestamp>=:start AND n.timestamp<:end AND r.mode=:mode
 AND (:mode='live' OR (r.dataset_id=CAST(:dataset AS uuid) AND r.run_id=CAST(:run AS uuid)))
), linked AS MATERIALIZED (
 SELECT DISTINCT o.event_id FROM public.entity_observations o
 JOIN identity i ON i.id=o.entity_id AND i.kind IN ('host','user')
 LEFT JOIN public.normalized_events n ON n.event_id=o.event_id
 WHERE (n.timestamp>=:start AND n.timestamp<:end)
 OR (o.timestamp>=:start AND o.timestamp<:end)
 LIMIT :sentinel_events
), proof_metadata AS MATERIALIZED (
 SELECT l.event_id,
  (SELECT COALESCE(jsonb_agg(to_jsonb(o) ORDER BY o.entity_id,o.role),'[]'::jsonb)
   FROM public.entity_observations o WHERE o.event_id=l.event_id) AS observations
 FROM linked l WHERE (SELECT count(*) FROM linked)<=:max_events
), state AS MATERIALIZED (
 SELECT (SELECT count(*) FROM linked) AS event_count,
 (SELECT count(*) FROM scoped WHERE indexed_id IS NULL) AS pending,
 EXISTS(SELECT 1 FROM scoped s WHERE s.indexed_id IS NOT NULL AND (
    s.receipt_hash<>s.document_sha256 OR s.identity_policy<>'entity-identity-v1'
    OR s.observation_count<>(SELECT count(*) FROM public.entity_observations o
                              WHERE o.event_id=s.event_id))) AS index_invalid,
 EXISTS(SELECT 1 FROM linked l
  LEFT JOIN public.normalized_events n ON n.event_id=l.event_id
  LEFT JOIN public.raw_events r ON r.id=l.event_id
  LEFT JOIN public.entity_index_receipts p ON p.event_id=l.event_id
  CROSS JOIN identity i
  WHERE n.event_id IS NULL OR r.id IS NULL OR p.event_id IS NULL
   OR r.mode<>i.mode OR r.source_id IS DISTINCT FROM i.source_id
   OR (i.mode='replay' AND (r.dataset_id<>i.dataset_id OR r.run_id<>i.run_id))
   OR (i.mode='live' AND r.run_id<>'00000000-0000-0000-0000-000000000000'::uuid)
   OR n.timestamp<:start OR n.timestamp>=:end) AS scope_invalid,
 COALESCE((SELECT sum(octet_length(to_jsonb(n)::text)+octet_length(to_jsonb(r)::text)
   +octet_length(to_jsonb(p)::text)+octet_length(m.observations::text))
   FROM linked l JOIN public.normalized_events n ON n.event_id=l.event_id
   JOIN public.raw_events r ON r.id=l.event_id
   JOIN public.entity_index_receipts p ON p.event_id=l.event_id
   JOIN proof_metadata m ON m.event_id=l.event_id),0) AS bytes
)
SELECT jsonb_build_object(
 'identity',(SELECT to_jsonb(i) FROM identity i),'event_count',s.event_count,
 'as_of',statement_timestamp(),
 'pending',s.pending,'integrity_mismatch',s.index_invalid OR s.scope_invalid,'bytes',s.bytes,
 'items',CASE WHEN s.event_count>:max_events OR s.bytes>:max_bytes
   OR s.index_invalid OR s.scope_invalid THEN '[]'::jsonb ELSE
 COALESCE((SELECT jsonb_agg(jsonb_build_object('normalized',to_jsonb(n),'raw',to_jsonb(r),
    'receipt',to_jsonb(p),'observations',m.observations) ORDER BY n.timestamp,n.event_id)
  FROM linked l JOIN public.normalized_events n ON n.event_id=l.event_id
  JOIN public.raw_events r ON r.id=l.event_id
  JOIN public.entity_index_receipts p ON p.event_id=l.event_id
  JOIN proof_metadata m ON m.event_id=l.event_id),'[]'::jsonb) END)
FROM state s
""")


def snapshot(
    db: Session, entity_id: UUID, filters: UebaFilters, start: datetime, end: datetime
) -> dict[str, Any]:
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    result: Any = db.scalar(
        _REPORT,
        {
            "entity": entity_id,
            "mode": filters.mode,
            "dataset": filters.dataset_id,
            "run": filters.run_id,
            "start": start,
            "end": end,
            "max_events": MAX_EVENTS,
            "sentinel_events": MAX_EVENTS + 1,
            "max_bytes": MAX_BYTES,
        },
    )
    assert isinstance(result, dict)
    return result
