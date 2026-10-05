"""One PostgreSQL snapshot per profile response, with indexed evidence joins and SQL bounds."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.entities.schemas import EntityFilters

# Read-only profile queries share their scope, totals, page and projection snapshot.
# Identifiers below are fixed application SQL; user input is always a bound value.
_COMMON = """
WITH scoped_events AS MATERIALIZED (
 SELECT n.event_id,n.timestamp,n.document,n.document_sha256,r.source_id
 FROM public.normalized_events n JOIN public.raw_events r ON r.id=n.event_id
 WHERE n.timestamp>=:start AND n.timestamp<:end AND n.processed_at<=:anchor AND r.mode=:mode AND
 (:mode='live' OR (r.dataset_id=CAST(:dataset AS uuid) AND r.run_id=CAST(:run AS uuid)))
), observations AS MATERIALIZED (
 SELECT o.*,n.document,n.source_id FROM public.entity_observations o
 JOIN scoped_events n ON n.event_id=o.event_id
 JOIN public.entity_index_receipts er ON er.event_id=o.event_id AND er.created_at<=:anchor
 WHERE o.document_sha256=n.document_sha256
), status AS (
 SELECT jsonb_build_object('pending_events',(
   SELECT count(*) FROM scoped_events n WHERE NOT EXISTS (
    SELECT 1 FROM public.entity_index_receipts p
    WHERE p.event_id=n.event_id AND p.created_at<=:anchor)),
 'pending_alerts',(
   SELECT count(*) FROM public.alerts a WHERE a.mode=:mode AND a.created_at<=:anchor AND
    (:mode='live' OR (a.dataset_id=CAST(:dataset AS uuid) AND a.run_id=CAST(:run AS uuid)))
    AND NOT EXISTS(SELECT 1 FROM public.entity_alert_receipts p
      WHERE p.alert_id=a.id AND p.created_at<=:anchor)
    AND (EXISTS(SELECT 1 FROM scoped_events n WHERE n.event_id=a.event_id) OR
      EXISTS(SELECT 1 FROM jsonb_array_elements(a.event_snapshots) proof
       JOIN scoped_events n ON n.event_id::text=proof->>'event_id')))) AS data
), candidates AS MATERIALIZED (
 SELECT i.* FROM public.entity_identities i
 WHERE i.created_at<=:anchor AND i.mode=:mode AND
 (:mode='live' OR (i.dataset_id=CAST(:dataset AS uuid) AND i.run_id=CAST(:run AS uuid)))
 AND (CAST(:kind AS text) IS NULL OR i.kind=:kind)
 AND (CAST(:search AS text) IS NULL OR strpos(lower(i.label),lower(:search))>0 OR EXISTS (
   SELECT 1 FROM observations o WHERE o.entity_id=i.id AND
    strpos(lower(COALESCE(o.attributes->>'host_name',o.attributes->>'user_name',
      o.attributes->>'process_name',i.label)),lower(:search))>0))
 AND EXISTS(SELECT 1 FROM observations o WHERE o.entity_id=i.id)
 AND (CAST(:identifier AS uuid) IS NULL OR i.id=CAST(:identifier AS uuid))
 AND (CAST(:event_id AS uuid) IS NULL OR EXISTS(SELECT 1 FROM observations o
   WHERE o.entity_id=i.id AND o.event_id=CAST(:event_id AS uuid)))
 AND (CAST(:related_id AS uuid) IS NULL OR (i.id<>CAST(:related_id AS uuid) AND EXISTS(
   SELECT 1 FROM observations own JOIN observations other ON other.event_id=own.event_id
    WHERE own.entity_id=CAST(:related_id AS uuid) AND other.entity_id=i.id)))
), selected AS MATERIALIZED (
 SELECT * FROM candidates WHERE (CAST(:after_time AS timestamptz) IS NULL OR
  (created_at,id)<(CAST(:after_time AS timestamptz),CAST(:after_id AS uuid)))
 ORDER BY created_at DESC,id DESC LIMIT :page_size
), activity AS MATERIALIZED (
 SELECT o.* FROM observations o JOIN selected i ON i.id=o.entity_id
), associated AS MATERIALIZED (
 SELECT DISTINCT o.entity_id,ref.alert_id FROM activity o
 JOIN public.alert_event_references ref ON ref.event_id=o.event_id
 JOIN public.entity_alert_receipts ar ON ar.alert_id=ref.alert_id AND ar.created_at<=:anchor
 JOIN public.alerts a ON a.id=ref.alert_id AND a.created_at<=:anchor
 WHERE a.mode=:mode AND (:mode='live' OR
  (a.dataset_id=CAST(:dataset AS uuid) AND a.run_id=CAST(:run AS uuid)))
), cases AS MATERIALIZED (
 SELECT DISTINCT s.entity_id,link.incident_id FROM associated s
 JOIN public.incident_alerts link ON link.alert_id=s.alert_id AND link.active
 JOIN public.incidents i ON i.id=link.incident_id
 WHERE i.created_at<=:anchor AND i.mode=:mode AND (:mode='live' OR
  (i.dataset_id=CAST(:dataset AS uuid) AND i.run_id=CAST(:run AS uuid)))
)
"""

_PROFILES = text(
    _COMMON
    + """
SELECT jsonb_build_object('total',(SELECT count(*) FROM candidates),
 'event_found',EXISTS(SELECT 1 FROM scoped_events WHERE event_id=CAST(:event_id AS uuid)),
 'related_found',EXISTS(SELECT 1 FROM observations WHERE entity_id=CAST(:related_id AS uuid)),
 'index_status',(SELECT data FROM status),
 'items',COALESCE((SELECT jsonb_agg(row.data ORDER BY row.created_at DESC,row.id DESC) FROM (
 SELECT i.id,i.created_at,jsonb_build_object(
  'identity',to_jsonb(i),
  'label',COALESCE((SELECT COALESCE(o.attributes->>'host_name',o.attributes->>'user_name',
    o.attributes->>'process_name') FROM activity o WHERE o.entity_id=i.id
    AND COALESCE(o.attributes->>'host_name',o.attributes->>'user_name',
      o.attributes->>'process_name') IS NOT NULL
    ORDER BY o.timestamp DESC,o.event_id DESC,o.role DESC LIMIT 1),i.label),
  'first_seen',(SELECT min(timestamp) FROM activity WHERE entity_id=i.id),
  'last_seen',(SELECT max(timestamp) FROM activity WHERE entity_id=i.id),
  'counts',jsonb_build_object(
    'events',(SELECT count(DISTINCT event_id) FROM activity WHERE entity_id=i.id),
    'observations',(SELECT count(*) FROM activity WHERE entity_id=i.id),
    'failed_logins',(SELECT count(DISTINCT event_id) FROM activity WHERE entity_id=i.id
      AND document->'event'->>'category'='authentication'
      AND document->'event'->>'outcome'='failure'),
    'alerts',(SELECT count(*) FROM associated WHERE entity_id=i.id),
    'eligible_alerts',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
      WHERE s.entity_id=i.id AND a.status<>'false_positive'),
    'false_positive_alerts',(SELECT count(*) FROM associated s
      JOIN public.alerts a ON a.id=s.alert_id
      WHERE s.entity_id=i.id AND a.status='false_positive'),
    'incidents',(SELECT count(*) FROM cases WHERE entity_id=i.id)),
  'roles',COALESCE((SELECT jsonb_object_agg(role,count) FROM (
    SELECT role,count(DISTINCT event_id) FROM activity WHERE entity_id=i.id GROUP BY role
  ) role_counts),'{}'::jsonb),
  'related_host_count',(SELECT count(DISTINCT other.entity_id) FROM activity own
     JOIN observations other ON other.event_id=own.event_id
     JOIN public.entity_identities host ON host.id=other.entity_id
     WHERE own.entity_id=i.id AND host.kind='host' AND host.id<>i.id),
  'assessed_alerts',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
    WHERE s.entity_id=i.id AND a.status<>'false_positive' AND a.risk_calculation_id IS NOT NULL),
  'invalid_risk',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
    LEFT JOIN public.risk_calculations rc ON rc.id=a.risk_calculation_id
    WHERE s.entity_id=i.id AND a.status<>'false_positive' AND a.risk_calculation_id IS NOT NULL AND
    (rc.id IS NULL OR rc.subject_type<>'alert' OR rc.subject_id<>a.id
      OR rc.mode<>a.mode OR rc.run_id<>a.run_id
      OR (a.mode='replay' AND rc.dataset_id IS DISTINCT FROM a.dataset_id)
      OR rc.score IS DISTINCT FROM a.risk_score OR rc.level IS DISTINCT FROM a.risk_level)),
  'risk',(SELECT jsonb_build_object('calculation',to_jsonb(rc),'alert_id',a.id,
      'proof',COALESCE((SELECT jsonb_agg(jsonb_build_object(
        'event_id',ref.event_id,'sha256',ref.document_sha256,'timestamp',n.timestamp))
        FROM public.alert_event_references ref
        JOIN public.normalized_events n ON n.event_id=ref.event_id
        WHERE ref.alert_id=a.id),'[]'::jsonb),
      'source',jsonb_build_object('id',a.id,'event_sha256',a.event_sha256,'rule_id',a.rule_id,
        'rule_version',a.rule_version,'evaluator_version',a.evaluator_version,'severity',a.severity)
        || CASE WHEN a.evaluator_version='sigma-subset-v1' THEN jsonb_build_object(
          'sigma_revision_id',a.rule_snapshot->>'revision_id',
          'sigma_source_sha256',a.rule_snapshot->>'source_sha256',
          'sigma_compiled_sha256',a.rule_snapshot->>'compiled_sha256') ELSE '{}'::jsonb END)
    FROM associated s JOIN public.alerts a ON a.id=s.alert_id
    JOIN public.risk_calculations rc ON rc.id=a.risk_calculation_id
    WHERE s.entity_id=i.id AND a.status<>'false_positive'
    ORDER BY rc.score DESC,rc.created_at DESC,a.id DESC LIMIT 1),
  'mitre',jsonb_build_object(
    'mapped_alerts',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
      JOIN public.alert_mitre_snapshots m ON m.alert_id=a.id
      WHERE s.entity_id=i.id AND a.status<>'false_positive'
       AND m.status='mapped' AND m.catalogue_hash=:catalogue),
    'unmapped_alerts',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
      JOIN public.alert_mitre_snapshots m ON m.alert_id=a.id
      WHERE s.entity_id=i.id AND a.status<>'false_positive'
       AND m.status='unmapped' AND m.catalogue_hash=:catalogue),
    'legacy_alerts',(SELECT count(*) FROM associated s JOIN public.alerts a ON a.id=s.alert_id
      LEFT JOIN public.alert_mitre_snapshots m ON m.alert_id=a.id WHERE s.entity_id=i.id
       AND a.status<>'false_positive' AND m.alert_id IS NULL),
    'other_catalogue_alerts',(SELECT count(*) FROM associated s
      JOIN public.alerts a ON a.id=s.alert_id JOIN public.alert_mitre_snapshots m ON m.alert_id=a.id
      WHERE s.entity_id=i.id AND a.status<>'false_positive'
       AND m.catalogue_hash<>:catalogue),
    'techniques',COALESCE((SELECT jsonb_agg(to_jsonb(tc)) FROM (
      SELECT mapping.technique_id AS id,count(DISTINCT a.id) AS alert_count FROM associated s
      JOIN public.alerts a ON a.id=s.alert_id AND a.status<>'false_positive'
      JOIN public.alert_mitre_snapshots m ON m.alert_id=a.id
        AND m.catalogue_hash=:catalogue AND m.status='mapped'
      JOIN public.alert_mitre_mappings mapping ON mapping.alert_id=a.id
      WHERE s.entity_id=i.id GROUP BY mapping.technique_id ORDER BY mapping.technique_id
    ) tc),'[]'::jsonb))
 ) AS data FROM selected i
) row),'[]'::jsonb))
"""
)


def parameters(
    filters: EntityFilters,
    anchor: datetime,
    after: tuple[datetime, UUID] | None,
    *,
    identifier: UUID | None = None,
    event_id: UUID | None = None,
    related_id: UUID | None = None,
) -> dict[str, Any]:
    from app.modules.mitre.catalogue import CATALOGUE_SHA256

    try:
        start, end = filters.window(anchor)
    except ValueError:
        raise ApiError(422, "invalid_entity_window", "Entity activity window is invalid") from None
    return {
        "start": start,
        "end": end,
        "anchor": anchor,
        "mode": filters.mode,
        "dataset": filters.dataset_id,
        "run": filters.run_id,
        "kind": filters.kind,
        "search": filters.q,
        "identifier": identifier,
        "event_id": event_id,
        "related_id": related_id,
        "after_time": after[0] if after else None,
        "after_id": after[1] if after else None,
        "page_size": filters.limit + 1,
        "catalogue": CATALOGUE_SHA256,
    }


def profiles(db: Session, params: dict[str, Any]) -> dict[str, Any]:
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    result: Any = db.scalar(_PROFILES, params)
    assert isinstance(result, dict)
    return result


_EVENT_ROWS = """
 SELECT o.event_id AS id,o.timestamp AS moment,jsonb_build_object(
  'event_id',o.event_id,'timestamp',o.timestamp,'source_id',o.source_id,
  'source_name',o.document->'source'->>'name','source_type',o.document->'source'->>'type',
  'event_category',o.document->'event'->>'category','event_action',o.document->'event'->>'action',
  'event_outcome',o.document->'event'->>'outcome',
  'roles',jsonb_agg(DISTINCT o.role ORDER BY o.role)) AS data
 FROM activity o GROUP BY o.event_id,o.timestamp,o.source_id,o.document
"""
_ALERT_ROWS = """
 SELECT a.id,a.created_at AS moment,jsonb_build_object(
  'id',a.id,'title',a.title,'rule_id',a.rule_id,'severity',a.severity,'status',a.status,
  'event_timestamp',a.event_timestamp,'contributing_event_count',p.contributor_count,
  'matched_entity_event_count',(SELECT count(DISTINCT o.event_id) FROM activity o
    JOIN public.alert_event_references r ON r.event_id=o.event_id WHERE r.alert_id=a.id),
  'risk_score',CASE WHEN a.status='false_positive' THEN NULL ELSE a.risk_score END,
  'risk_level',CASE WHEN a.status='false_positive' THEN NULL ELSE a.risk_level END) AS data
 FROM associated s JOIN public.alerts a ON a.id=s.alert_id
 JOIN public.entity_alert_receipts p ON p.alert_id=a.id
"""
_INCIDENT_ROWS = """
 SELECT i.id,i.created_at AS moment,jsonb_build_object(
  'id',i.id,'title',i.title,'severity',i.severity,'status',i.status,'created_at',i.created_at,
  'matched_alert_count',(SELECT count(DISTINCT s.alert_id) FROM associated s
    JOIN public.incident_alerts link ON link.alert_id=s.alert_id
      AND link.active AND link.incident_id=i.id),
  'risk_score',i.risk_score,'risk_level',i.risk_level) AS data
 FROM cases c JOIN public.incidents i ON i.id=c.incident_id
"""


def _collection_statement(rows: str) -> Any:
    return text(
        _COMMON
        + ", collection AS MATERIALIZED ("
        + rows
        + """
), page AS (
 SELECT * FROM collection WHERE (CAST(:item_after_time AS timestamptz) IS NULL OR
   (moment,id)<(CAST(:item_after_time AS timestamptz),CAST(:item_after_id AS uuid)))
 ORDER BY moment DESC,id DESC LIMIT :page_size
)
SELECT jsonb_build_object('entity_found',EXISTS(SELECT 1 FROM selected),
 'total',(SELECT count(*) FROM collection),'index_status',(SELECT data FROM status),
 'items',COALESCE((SELECT jsonb_agg(jsonb_build_object('data',p.data,'moment',p.moment,'id',p.id)
  ORDER BY p.moment DESC,p.id DESC) FROM page p),'[]'::jsonb))
"""
    )


_COLLECTIONS = {
    "events": _collection_statement(_EVENT_ROWS),
    "alerts": _collection_statement(_ALERT_ROWS),
    "incidents": _collection_statement(_INCIDENT_ROWS),
}


def collection(
    db: Session, kind: str, params: dict[str, Any], after: tuple[datetime, UUID] | None
) -> dict[str, Any]:
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    query = _COLLECTIONS[kind]
    result: Any = db.scalar(
        query,
        {
            **params,
            "after_time": None,
            "after_id": None,
            "item_after_time": after[0] if after else None,
            "item_after_id": after[1] if after else None,
        },
    )
    assert isinstance(result, dict)
    return result
