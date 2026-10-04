"""Own authored Sigma examples and real normalized source proof for tests."""

import json
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.modules.alerts.models import Alert
from app.modules.audit.models import AuditLog
from app.modules.detections.models import DetectionJob, RuleDeployment
from app.modules.incidents.models import Incident
from app.modules.mitre.models import AlertMitreSnapshot
from app.modules.normalization.models import NormalizedEvent
from app.modules.risk.models import RiskCalculation
from app.modules.sigma.models import SigmaRule, SigmaRuleVersion

from .helpers import Case, Login


def definition(identity: str | UUID | None = None, **metadata: Any) -> str:
    return json.dumps(
        {
            "title": "Reviewable Sigma process fixture",
            "id": str(identity or uuid4()),
            "level": "high",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"CommandLine|contains": "get-date"},
                "condition": "selection",
            },
            "tags": ["attack.t1059.001"],
            **metadata,
        },
        ensure_ascii=False,
    )


def import_rule(principal: Login, source: str | None = None) -> dict[str, Any]:
    response = principal.client.post(
        "/api/v1/sigma/rules",
        json={"yaml": source or definition()},
        headers=principal.authorization,
    )
    assert response.status_code == 201, response.text
    assert response.headers["etag"] == '"1"'
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


def publish(principal: Login, rule: dict[str, Any], enabled: bool = True) -> dict[str, Any]:
    response = principal.client.patch(
        f"/api/v1/sigma/rules/{rule['id']}",
        json={"enabled": enabled},
        headers={**principal.authorization, "If-Match": f'"{rule["version"]}"'},
    )
    assert response.status_code == 200, response.text
    assert response.headers["etag"] == f'"{response.json()["version"]}"'
    return dict(response.json())


def domain_counts(case: Case) -> dict[str, int]:
    with Session(case.database.runtime) as db:
        return {
            model.__tablename__: int(db.scalar(select(func.count()).select_from(model)) or 0)
            for model in (
                SigmaRule,
                SigmaRuleVersion,
                RuleDeployment,
                Alert,
                DetectionJob,
                RiskCalculation,
                Incident,
                AlertMitreSnapshot,
                AuditLog,
            )
        }


def document(case: Case, event_id: UUID) -> dict[str, Any]:
    with Session(case.database.runtime) as db:
        row = db.get(NormalizedEvent, event_id)
        assert row is not None
        return dict(row.document)
