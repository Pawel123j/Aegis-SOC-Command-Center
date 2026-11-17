"""Exact aggregates share a snapshot; no ClickHouse duplicates or sampled event lists."""

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.dashboard.schemas import DashboardFilters, DashboardReport
from app.modules.mitre.catalogue import CATALOGUE_SHA256, catalogue_view

_QUERY = text("""
WITH events AS MATERIALIZED (
 SELECT n.event_id,n.timestamp,n.document_sha256
 FROM public.normalized_events n JOIN public.raw_events r ON r.id=n.event_id
 WHERE n.timestamp>=:start AND n.timestamp<:end AND r.mode=:mode
 AND (:mode='live' OR (r.dataset_id=CAST(:dataset AS uuid) AND r.run_id=CAST(:run AS uuid)))
), received AS MATERIALIZED (
 SELECT id,received_at FROM public.raw_events
 WHERE received_at>=:start AND received_at<:end AND mode=:mode
 AND (:mode='live' OR (dataset_id=CAST(:dataset AS uuid) AND run_id=CAST(:run AS uuid)))
), scoped_alerts AS MATERIALIZED (
 SELECT id,status,severity,risk_level,rule_id,rule_version,title FROM public.alerts
 WHERE event_timestamp>=:start AND event_timestamp<:end AND mode=:mode
 AND (:mode='live' OR (dataset_id=CAST(:dataset AS uuid) AND run_id=CAST(:run AS uuid)))
), alerts AS MATERIALIZED (
 SELECT * FROM scoped_alerts WHERE :include_fp OR status<>'false_positive'
), cases AS MATERIALIZED (
 SELECT severity FROM public.incidents WHERE status IN ('new','investigating','contained')
 AND mode=:mode AND (:mode='live' OR
 (dataset_id=CAST(:dataset AS uuid) AND run_id=CAST(:run AS uuid)))
), receipts AS MATERIALIZED (
 SELECT n.event_id,n.document_sha256,p.document_sha256 AS receipt_hash,p.observation_count
 FROM events n LEFT JOIN public.entity_index_receipts p ON p.event_id=n.event_id
), observations AS MATERIALIZED (
 SELECT o.*,i.kind,i.label,i.identity_basis,
 i.mode AS entity_mode,i.dataset_id AS entity_dataset,i.run_id AS entity_run
 FROM public.entity_observations o JOIN events n ON n.event_id=o.event_id
 JOIN public.entity_identities i ON i.id=o.entity_id
), entity_counts AS MATERIALIZED (
 SELECT CASE WHEN kind='user' THEN 'users' WHEN kind='host' THEN 'hosts'
 WHEN kind='ip' AND role='source' THEN 'source_ips'
 WHEN kind='ip' AND role='destination' THEN 'destination_ips' END AS bucket,
 entity_id AS id,label,identity_basis,count(DISTINCT event_id) AS count
 FROM observations GROUP BY bucket,entity_id,label,identity_basis
), ranked AS (
 SELECT *,row_number() OVER (PARTITION BY bucket ORDER BY count DESC,id) AS rank
 FROM entity_counts WHERE bucket IS NOT NULL
), mappings AS MATERIALIZED (
 SELECT a.id,s.status,s.catalogue_hash FROM alerts a
 LEFT JOIN public.alert_mitre_snapshots s ON s.alert_id=a.id
), tactics AS (
 SELECT m.tactic_id AS id,count(DISTINCT m.alert_id) AS count
 FROM public.alert_mitre_mappings m JOIN mappings s ON s.id=m.alert_id
 WHERE s.status='mapped' AND s.catalogue_hash=:catalogue GROUP BY m.tactic_id
), rate AS (
 SELECT floor(extract(epoch FROM (received_at-CAST(:rate_start AS timestamptz)))/60)::int
 AS bucket,count(*) AS count FROM received WHERE received_at>=:rate_start GROUP BY bucket
)
SELECT jsonb_build_object(
 'counts',jsonb_build_object(
  'events_24h',(SELECT count(*) FROM events),
  'alerts_24h',(SELECT count(*) FROM alerts),
  'excluded_false_positives',(SELECT count(*) FROM scoped_alerts
     WHERE NOT :include_fp AND status='false_positive'),
  'open_incidents',(SELECT count(*) FROM cases),
  'critical_incidents',(SELECT count(*) FROM cases WHERE severity='critical'),
  'received_24h',(SELECT count(*) FROM received)),
 'index_status',jsonb_build_object(
  'pending_events',(SELECT count(*) FROM receipts WHERE receipt_hash IS NULL),
  'indexed_events',(SELECT count(*) FROM receipts WHERE receipt_hash IS NOT NULL),
  'entities_partial',EXISTS(SELECT 1 FROM receipts WHERE receipt_hash IS NULL)),
 'invalid_index',EXISTS(SELECT 1 FROM receipts r WHERE receipt_hash IS NOT NULL AND
  (document_sha256<>receipt_hash OR observation_count<>(
    SELECT count(*) FROM observations o WHERE o.event_id=r.event_id)))
 OR EXISTS(SELECT 1 FROM observations o JOIN receipts r ON r.event_id=o.event_id
  WHERE r.receipt_hash IS NULL OR o.document_sha256<>r.document_sha256
   OR o.entity_mode<>:mode OR (:mode='replay' AND
     (o.entity_dataset IS DISTINCT FROM CAST(:dataset AS uuid)
      OR o.entity_run<>CAST(:run AS uuid)))),
 'entities',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY bucket,count DESC,id)
  FROM ranked r WHERE rank<=10),'[]'::jsonb),
 'rules',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY count DESC,id,version) FROM (
  SELECT rule_id AS id,rule_version AS version,min(title) AS label,count(*) AS count
  FROM alerts GROUP BY rule_id,rule_version ORDER BY count DESC,id,version LIMIT 10
 ) r),'[]'::jsonb),
 'severity',COALESCE((SELECT jsonb_object_agg(severity,count) FROM (
  SELECT severity,count(*) AS count FROM alerts GROUP BY severity) s),'{}'::jsonb),
 'risk',COALESCE((SELECT jsonb_object_agg(level,count) FROM (
  SELECT COALESCE(risk_level,'unassessed') AS level,count(*) AS count
  FROM alerts GROUP BY level) s),'{}'::jsonb),
 'tactics',COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY count DESC,id)
  FROM tactics t),'[]'::jsonb),
 'mitre_status',jsonb_build_object(
  'mapped_alerts',(SELECT count(*) FROM mappings
    WHERE status='mapped' AND catalogue_hash=:catalogue),
  'unmapped_alerts',(SELECT count(*) FROM mappings
    WHERE status='unmapped' AND catalogue_hash=:catalogue),
  'missing_snapshots',(SELECT count(*) FROM mappings WHERE status IS NULL),
  'other_catalogue_alerts',(SELECT count(*) FROM mappings WHERE catalogue_hash<>:catalogue)),
 'rate',COALESCE((SELECT jsonb_object_agg(bucket,count) FROM rate),'{}'::jsonb)
)
""")

_SEVERITIES = {
    "critical": "Krytyczna",
    "high": "Wysoka",
    "medium": "Średnia",
    "low": "Niska",
    "informational": "Informacyjna",
}
_RISKS = {
    "critical": "Krytyczne",
    "high": "Wysokie",
    "medium": "Średnie",
    "low": "Niskie",
    "unassessed": "Brak oceny",
}


def dashboard(db: Session, filters: DashboardFilters, now: datetime) -> DashboardReport:
    try:
        start, end = filters.window(now)
    except ValueError:
        raise ApiError(422, "invalid_dashboard_window", "Dashboard window is invalid") from None
    rate_start = end - timedelta(hours=1)
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    raw: Any = db.scalar(
        _QUERY,
        {
            "start": start,
            "end": end,
            "mode": filters.mode,
            "dataset": filters.dataset_id,
            "run": filters.run_id,
            "include_fp": filters.include_false_positives,
            "rate_start": rate_start,
            "catalogue": CATALOGUE_SHA256,
        },
    )
    if not isinstance(raw, dict) or raw["invalid_index"]:
        raise ApiError(409, "dashboard_index_integrity", "Dashboard index needs review")
    names = {item.id: item.name for item in catalogue_view().tactics}
    if any(item["id"] not in names for item in raw["tactics"]):
        raise ApiError(409, "dashboard_mapping_integrity", "Stored mappings need review")
    top: dict[str, list[dict[str, Any]]] = {
        name: [] for name in ("users", "hosts", "source_ips", "destination_ips")
    }
    for item in raw["entities"]:
        top[item["bucket"]].append(
            {key: item[key] for key in ("id", "label", "identity_basis", "count")}
        )
    counts = [int(raw["rate"].get(str(index), 0)) for index in range(60)]
    return DashboardReport.model_validate(
        {
            "generated_at": now,
            "scope": {
                "mode": filters.mode,
                "dataset_id": filters.dataset_id,
                "run_id": filters.run_id,
                "from": start,
                "to": end,
                "include_false_positives": filters.include_false_positives,
            },
            "counts": raw["counts"],
            "index_status": raw["index_status"],
            "top": top,
            "rules": raw["rules"],
            "severity": [
                {"id": key, "label": label, "count": raw["severity"].get(key, 0)}
                for key, label in _SEVERITIES.items()
            ],
            "risk": [
                {"id": key, "label": label, "count": raw["risk"].get(key, 0)}
                for key, label in _RISKS.items()
            ],
            "tactics": [{**item, "label": names[item["id"]]} for item in raw["tactics"]],
            "mitre_status": raw["mitre_status"],
            "ingestion": {
                "accepted_events": sum(counts),
                "average_eps": sum(counts) / 3600,
                "buckets": [
                    {
                        "from": rate_start + timedelta(minutes=i),
                        "to": rate_start + timedelta(minutes=i + 1),
                        "count": count,
                        "events_per_second": count / 60,
                    }
                    for i, count in enumerate(counts)
                ],
            },
        }
    )
