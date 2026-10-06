"""One PostgreSQL snapshot for bounded metadata, page proof and view fingerprint."""

from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.modules.attack_timeline.cursors import Position

PAGE_BYTES = 4 * 1024 * 1024

# Fixed identifiers and bound values only. Full JSON documents are returned only
# after the uncompressed source/reference budget passes. Unselected evidence remains
# in PostgreSQL; its source document is not claimed to have been verified here.
_TIMELINE = text("""
WITH case_row AS MATERIALIZED (
 SELECT id,version,mode,dataset_id,run_id FROM public.incidents WHERE id=:incident_id
), links AS MATERIALIZED (
 SELECT l.id AS link_id,l.alert_id,l.linked_at FROM case_row i
 JOIN public.incident_alerts l ON l.incident_id=i.id AND l.active
 ORDER BY l.id LIMIT 101
), alerts AS MATERIALIZED (
 SELECT l.*,a.id,a.version,a.mode,a.dataset_id,a.run_id,a.title,a.severity,a.status,
  a.rule_id,a.rule_version,a.evaluator_version,a.event_id,a.event_timestamp,a.source_id,
  jsonb_array_length(a.event_snapshots) AS evidence_count,
  p.contributor_count,p.created_at AS receipt_at,
  n.timestamp AS anchor_timestamp,r.source_id AS anchor_source,r.dataset_id AS anchor_dataset,
  r.mode AS anchor_mode,r.run_id AS anchor_run
 FROM links l LEFT JOIN public.alerts a ON a.id=l.alert_id
 LEFT JOIN public.entity_alert_receipts p ON p.alert_id=a.id
 LEFT JOIN public.normalized_events n ON n.event_id=a.event_id
 LEFT JOIN public.raw_events r ON r.id=a.event_id
 WHERE (SELECT count(*) FROM links)<=100
), refs AS MATERIALIZED (
 SELECT a.id AS alert_id,ref.event_id,ref.document_sha256,n.timestamp,
  n.document_sha256 AS normalized_hash,r.id AS raw_id,r.mode,r.dataset_id,r.run_id
 FROM alerts a JOIN LATERAL (
   SELECT event_id,document_sha256 FROM public.alert_event_references
   WHERE alert_id=a.id ORDER BY event_id LIMIT 101
 ) ref ON true
 LEFT JOIN public.normalized_events n ON n.event_id=ref.event_id
 LEFT JOIN public.raw_events r ON r.id=ref.event_id
), readiness AS MATERIALIZED (
 SELECT a.*,(SELECT count(*) FROM refs r WHERE r.alert_id=a.id) AS reference_count
 FROM alerts a
), state AS MATERIALIZED (
 SELECT (SELECT count(*) FROM links)>100 OR EXISTS(
   SELECT 1 FROM readiness WHERE reference_count>100 OR contributor_count>100
    OR evidence_count>100) AS limit_exceeded,
  (EXISTS(SELECT 1 FROM case_row WHERE (
    (mode='live' AND dataset_id IS NULL AND run_id='00000000-0000-0000-0000-000000000000')
    OR (mode='replay' AND dataset_id IS NOT NULL
     AND dataset_id<>'00000000-0000-0000-0000-000000000000'
     AND run_id<>'00000000-0000-0000-0000-000000000000')) IS NOT TRUE)
   OR EXISTS(SELECT 1 FROM readiness a CROSS JOIN case_row i WHERE
    (a.id IS NOT NULL AND a.mode=i.mode AND a.run_id=i.run_id
     AND (i.mode='live' OR a.dataset_id=i.dataset_id)
     AND a.anchor_mode=a.mode AND a.anchor_run=a.run_id
     AND a.anchor_dataset=a.dataset_id AND a.anchor_source=a.source_id
     AND a.anchor_timestamp=a.event_timestamp
     AND a.evidence_count IS NOT NULL AND a.evidence_count>=0
     AND (a.evidence_count>0 OR a.evaluator_version NOT LIKE 'correlation-%')
     AND ((a.receipt_at IS NULL AND a.reference_count=0 AND a.contributor_count IS NULL)
       OR (a.receipt_at IS NOT NULL AND a.contributor_count>=1
         AND a.contributor_count=a.reference_count
         AND a.contributor_count=CASE WHEN a.evidence_count=0 THEN 1
                                      ELSE a.evidence_count END))) IS NOT TRUE)
   OR EXISTS(SELECT 1 FROM refs r CROSS JOIN case_row i WHERE
    (r.raw_id IS NOT NULL AND r.timestamp IS NOT NULL
     AND r.document_sha256=r.normalized_hash
     AND r.document_sha256 ~ '^[0-9a-f]{64}$'
     AND r.mode=i.mode AND r.run_id=i.run_id
     AND (i.mode='live' OR r.dataset_id=i.dataset_id)) IS NOT TRUE)) AS integrity_mismatch,
  encode(sha256(convert_to(jsonb_build_object(
    'case',(SELECT to_jsonb(i) FROM case_row i),
    'alerts',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'link_id',a.link_id,'linked_at',a.linked_at,'id',a.id,'version',a.version,
      'mode',a.mode,'dataset_id',a.dataset_id,'run_id',a.run_id,
      'title',a.title,'severity',a.severity,'status',a.status,
      'rule_id',a.rule_id,'rule_version',a.rule_version,'evaluator',a.evaluator_version,
      'receipt_at',a.receipt_at,'contributor_count',a.contributor_count,
      'references',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'event_id',r.event_id,'sha256',r.document_sha256,'timestamp',r.timestamp)
        ORDER BY r.event_id) FROM refs r WHERE r.alert_id=a.id),'[]'::jsonb))
      ORDER BY a.link_id) FROM readiness a),'[]'::jsonb))::text,'UTF8')),'hex')
    AS fingerprint
), events AS MATERIALIZED (
 SELECT DISTINCT r.event_id,r.timestamp FROM refs r JOIN readiness a ON a.id=r.alert_id
 WHERE a.receipt_at IS NOT NULL AND a.reference_count<=100
), candidates AS MATERIALIZED (
 SELECT * FROM events WHERE CAST(:after_time AS timestamptz) IS NULL OR
  (timestamp,event_id)>(CAST(:after_time AS timestamptz),CAST(:after_id AS uuid))
 ORDER BY timestamp,event_id LIMIT :page_size
), page AS MATERIALIZED (
 SELECT * FROM candidates ORDER BY timestamp,event_id LIMIT :limit
), reference_views AS MATERIALIZED (
 SELECT p.event_id,jsonb_agg(jsonb_build_object(
   'id',a.id,'title',a.title,'severity',a.severity,'status',a.status,
   'detection_type',CASE WHEN a.evaluator_version LIKE 'correlation-%' THEN 'correlation'
     WHEN a.evaluator_version LIKE 'sigma-%' THEN 'sigma'
     WHEN a.evaluator_version LIKE 'intelligence-%' THEN 'intelligence' ELSE 'single_event' END,
   'rule_id',a.rule_id,'rule_version',a.rule_version,'linked_at',a.linked_at)
   ORDER BY a.id) AS data
 FROM page p JOIN refs ref ON ref.event_id=p.event_id
 JOIN readiness a ON a.id=ref.alert_id AND a.receipt_at IS NOT NULL
 GROUP BY p.event_id
), source_budget AS MATERIALIZED (
 SELECT COALESCE((SELECT sum(octet_length(to_jsonb(n)::text)+octet_length(to_jsonb(r)::text))
   FROM page p JOIN public.normalized_events n ON n.event_id=p.event_id
   JOIN public.raw_events r ON r.id=p.event_id),0)
   + COALESCE((SELECT sum(octet_length(data::text)) FROM reference_views),0) AS bytes
), selected_refs AS MATERIALIZED (
 SELECT p.event_id,r.alert_id FROM page p JOIN refs r ON r.event_id=p.event_id
 JOIN readiness a ON a.id=r.alert_id AND a.receipt_at IS NOT NULL
), array_proofs AS MATERIALIZED (
 SELECT a.id AS alert_id,proof.event_id,proof.id_count,proof.valid_count
 FROM readiness a JOIN public.alerts original ON original.id=a.id
 JOIN LATERAL (
   SELECT selected.event_id,count(*) AS id_count,
    count(*) FILTER(WHERE e->>'event_sha256'=n.document_sha256
     AND e->'event_snapshot'=n.document) AS valid_count
   FROM jsonb_array_elements(original.event_snapshots) e
   JOIN selected_refs selected ON selected.alert_id=a.id
    AND e->>'event_id'=selected.event_id::text
   JOIN public.normalized_events n ON n.event_id=selected.event_id
   GROUP BY selected.event_id
 ) proof ON true
 WHERE a.evidence_count>0 AND (SELECT bytes FROM source_budget)<=:page_bytes
  AND NOT (SELECT limit_exceeded OR integrity_mismatch FROM state)
), copies AS MATERIALIZED (
 SELECT selected.event_id,a.id AS alert_id,
  CASE WHEN a.evidence_count=0 THEN
    (original.event_id=selected.event_id AND original.event_sha256=n.document_sha256
     AND original.event_snapshot=n.document)
  ELSE (
    proof.id_count=1 AND proof.valid_count=1
    AND (original.event_id<>selected.event_id OR
      (original.event_sha256=n.document_sha256 AND original.event_snapshot=n.document)))
  END AS equal
 FROM selected_refs selected JOIN readiness a ON a.id=selected.alert_id
 JOIN public.alerts original ON original.id=a.id
 JOIN public.normalized_events n ON n.event_id=selected.event_id
 LEFT JOIN array_proofs proof ON proof.alert_id=a.id AND proof.event_id=selected.event_id
 WHERE (SELECT bytes FROM source_budget)<=:page_bytes
  AND NOT (SELECT limit_exceeded OR integrity_mismatch FROM state)
), budget AS MATERIALIZED (
 SELECT (SELECT bytes FROM source_budget) AS bytes,
  EXISTS(SELECT 1 FROM copies WHERE equal IS NOT TRUE) AS copy_mismatch
)
SELECT jsonb_build_object(
 'incident',(SELECT to_jsonb(i) FROM case_row i),
 'limit_exceeded',s.limit_exceeded,'integrity_mismatch',s.integrity_mismatch OR b.copy_mismatch,
 'fingerprint',s.fingerprint,'page_bytes',b.bytes,
 'total',(SELECT count(*) FROM events),
 'index_status',jsonb_build_object(
   'eligible_alerts',(SELECT count(*) FROM links),
   'indexed_alerts',(SELECT count(*) FROM readiness WHERE receipt_at IS NOT NULL),
   'pending_alerts',(SELECT count(*) FROM readiness WHERE receipt_at IS NULL),
   'complete',NOT EXISTS(SELECT 1 FROM readiness WHERE receipt_at IS NULL)),
 'has_more',(SELECT count(*) FROM candidates)>:limit,
 'items',CASE WHEN s.limit_exceeded OR s.integrity_mismatch OR b.copy_mismatch
   OR b.bytes>:page_bytes
   OR (CAST(:fingerprint AS text) IS NOT NULL AND :fingerprint<>s.fingerprint)
 THEN '[]'::jsonb ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'normalized',to_jsonb(n),'raw',to_jsonb(r),
   'alerts',(SELECT data FROM reference_views v WHERE v.event_id=p.event_id))
   ORDER BY p.timestamp,p.event_id)
  FROM page p JOIN public.normalized_events n ON n.event_id=p.event_id
  JOIN public.raw_events r ON r.id=p.event_id),'[]'::jsonb) END)
FROM state s CROSS JOIN budget b
""")


def timeline(
    db: Session, incident_id: UUID, limit: int, position: Position | None
) -> dict[str, Any]:
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    result: Any = db.scalar(
        _TIMELINE,
        {
            "incident_id": incident_id,
            "after_time": position.moment if position else None,
            "after_id": position.event_id if position else None,
            "fingerprint": position.fingerprint if position else None,
            "limit": limit,
            "page_size": limit + 1,
            "page_bytes": PAGE_BYTES,
        },
    )
    assert isinstance(result, dict)
    return result
