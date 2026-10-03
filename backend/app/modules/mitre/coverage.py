"""One bounded SQL snapshot counts eligible associations, cases and deployment state."""

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.detections.builtin import BUILTIN_RULES
from app.modules.mitre.catalogue import CATALOGUE_SHA256, catalogue_view
from app.modules.mitre.mapping import rule_mapping
from app.modules.mitre.schemas import (
    CoverageFilters,
    CoverageScope,
    CoverageSummary,
    CoverageView,
    TacticCoverage,
    TechniqueCoverage,
)

_AGGREGATE = text("""
WITH scoped AS MATERIALIZED (
  SELECT id,status FROM public.alerts
  WHERE mode=:mode AND event_timestamp>=:start AND event_timestamp<:end
    AND (:mode='live' OR (dataset_id=CAST(:dataset AS uuid) AND run_id=CAST(:run AS uuid)))
), eligible AS MATERIALIZED (
  SELECT id FROM scoped WHERE :include_fp OR status<>'false_positive'
), classified AS MATERIALIZED (
  SELECT e.id,s.status,s.catalogue_hash FROM eligible e
  LEFT JOIN public.alert_mitre_snapshots s ON s.alert_id=e.id
), mapped AS MATERIALIZED (
  SELECT m.alert_id,m.technique_id,m.tactic_id
  FROM public.alert_mitre_mappings m JOIN classified c ON c.id=m.alert_id
  WHERE c.status='mapped' AND c.catalogue_hash=:catalogue
), linked AS MATERIALIZED (
  SELECT DISTINCT e.id AS alert_id,link.incident_id
  FROM eligible e JOIN public.incident_alerts link ON link.alert_id=e.id AND link.active
  JOIN public.incidents i ON i.id=link.incident_id
  WHERE i.mode=:mode AND (:mode='live' OR (i.dataset_id=CAST(:dataset AS uuid)
    AND i.run_id=CAST(:run AS uuid)))
), techniques AS (
  SELECT m.technique_id AS id,count(DISTINCT m.alert_id) AS alert_count,
    count(DISTINCT l.incident_id) AS incident_count
  FROM mapped m LEFT JOIN linked l ON l.alert_id=m.alert_id GROUP BY m.technique_id
), tactics AS (
  SELECT m.tactic_id AS id,count(DISTINCT m.alert_id) AS alert_count,
    count(DISTINCT l.incident_id) AS incident_count
  FROM mapped m LEFT JOIN linked l ON l.alert_id=m.alert_id GROUP BY m.tactic_id
)
SELECT jsonb_build_object(
  'eligible_alerts',(SELECT count(*) FROM eligible),
  'mapped_alerts',(SELECT count(*) FROM classified
    WHERE status='mapped' AND catalogue_hash=:catalogue),
  'unmapped_alerts',(SELECT count(*) FROM classified
    WHERE status='unmapped' AND catalogue_hash=:catalogue),
  'legacy_alerts',(SELECT count(*) FROM classified WHERE status IS NULL),
  'other_catalogue_alerts',(SELECT count(*) FROM classified WHERE catalogue_hash<>:catalogue),
  'excluded_false_positive_alerts',(SELECT count(*) FROM scoped
    WHERE status='false_positive' AND NOT :include_fp),
  'incidents',(SELECT count(DISTINCT incident_id) FROM linked),
  'techniques',COALESCE((SELECT jsonb_agg(to_jsonb(t)) FROM techniques t),'[]'::jsonb),
  'tactics',COALESCE((SELECT jsonb_agg(to_jsonb(t)) FROM tactics t),'[]'::jsonb),
  'deployments',COALESCE((SELECT jsonb_object_agg(id,
    jsonb_build_object('version',rule_version,'enabled',enabled))
    FROM public.rule_deployments WHERE id=ANY(CAST(:rule_ids AS text[]))),'{}'::jsonb)
)
""")


def coverage(db: Session, filters: CoverageFilters, now: datetime) -> CoverageView:
    try:
        start, end = filters.window(now)
    except ValueError:
        raise ApiError(422, "invalid_coverage_window", "Coverage window is invalid") from None
    rules = (*BUILTIN_RULES, *CORRELATION_RULES)
    # Time-bounded indexed aggregation is additionally bounded by PostgreSQL.
    db.execute(text("SET LOCAL statement_timeout = '3000ms'"))
    raw: Any = db.scalar(
        _AGGREGATE,
        {
            "mode": filters.mode,
            "start": start,
            "end": end,
            "dataset": filters.dataset_id,
            "run": filters.run_id,
            "include_fp": filters.include_false_positives,
            "catalogue": CATALOGUE_SHA256,
            "rule_ids": [rule.id for rule in rules],
        },
    )
    assert isinstance(raw, dict)
    catalogue = catalogue_view()
    technique_counts = {row["id"]: row for row in raw["techniques"]}
    tactic_counts = {row["id"]: row for row in raw["tactics"]}
    if not set(technique_counts).issubset({item.id for item in catalogue.techniques}) or not set(
        tactic_counts
    ).issubset({item.id for item in catalogue.tactics}):
        raise ApiError(503, "mitre_mapping_unavailable", "Stored associations are unavailable")
    configured_techniques: dict[str, set[str]] = {}
    configured_tactics: dict[str, set[str]] = {}
    enabled_techniques: dict[str, set[str]] = {}
    enabled_tactics: dict[str, set[str]] = {}
    for rule in rules:
        deployment = raw["deployments"].get(rule.id)
        if deployment is None or deployment["version"] != rule.version:
            raise ApiError(503, "rules_unavailable", "Rule deployment version is unavailable")
        for technique in rule_mapping(rule.id).techniques:
            configured_techniques.setdefault(technique.id, set()).add(rule.id)
            if deployment["enabled"]:
                enabled_techniques.setdefault(technique.id, set()).add(rule.id)
            for tactic in technique.tactics:
                configured_tactics.setdefault(tactic.id, set()).add(rule.id)
                if deployment["enabled"]:
                    enabled_tactics.setdefault(tactic.id, set()).add(rule.id)
    return CoverageView(
        catalogue=catalogue.catalogue,
        scope=CoverageScope(
            mode=filters.mode,
            from_=start,
            to=end,
            dataset_id=filters.dataset_id,
            run_id=filters.run_id,
            include_false_positives=filters.include_false_positives,
        ),
        techniques=[
            TechniqueCoverage(
                **item.model_dump(),
                configured_rule_count=len(configured_techniques.get(item.id, set())),
                enabled_rule_count=len(enabled_techniques.get(item.id, set())),
                alert_count=technique_counts.get(item.id, {}).get("alert_count", 0),
                incident_count=technique_counts.get(item.id, {}).get("incident_count", 0),
            )
            for item in catalogue.techniques
        ],
        tactics=[
            TacticCoverage(
                **item.model_dump(),
                configured_rule_count=len(configured_tactics.get(item.id, set())),
                enabled_rule_count=len(enabled_tactics.get(item.id, set())),
                alert_count=tactic_counts.get(item.id, {}).get("alert_count", 0),
                incident_count=tactic_counts.get(item.id, {}).get("incident_count", 0),
            )
            for item in catalogue.tactics
        ],
        summary=CoverageSummary(
            **{
                key: value
                for key, value in raw.items()
                if key not in {"techniques", "tactics", "deployments"}
            },
            observed_techniques=len(technique_counts),
            observed_tactics=len(tactic_counts),
            configured_techniques=len(configured_techniques),
            enabled_techniques=len(enabled_techniques),
            configured_tactics=len(configured_tactics),
            enabled_tactics=len(enabled_tactics),
        ),
    )
