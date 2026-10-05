"""Fixed, versioned local IOC association alert; no behavioural claim."""

import hashlib
from dataclasses import dataclass
from typing import Any, Literal

from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.catalogue import metadata
from app.modules.mitre.schemas import MappingView

RULE_ID = "ti:malicious-indicator"
RULE_VERSION = "1.0.0"
EVALUATOR_VERSION = "intelligence-match-v1"


@dataclass(frozen=True)
class IntelligenceRule:
    deployment_version: int
    id: str = RULE_ID
    version: str = RULE_VERSION
    severity: Literal["medium"] = "medium"
    title: str = "Dopasowanie złośliwego IOC"

    def snapshot(self) -> dict[str, Any]:
        return {**rule_snapshot(), "deployment_version": self.deployment_version}


@dataclass(frozen=True)
class IntelligenceMatch:
    rule: IntelligenceRule
    reason: dict[str, Any]


def rule_snapshot() -> dict[str, Any]:
    return {
        "id": RULE_ID,
        "version": RULE_VERSION,
        "title": "Dopasowanie złośliwego IOC",
        "description": "Dokładne dopasowanie pola zdarzenia do aktywnej lokalnej rewizji IOC "
        "o zadeklarowanej reputacji malicious. To skojarzenie do oceny, nie potwierdzenie ataku.",
        "severity": "medium",
        "type": "intelligence",
        "evaluator_version": EVALUATOR_VERSION,
        "mitre": [],
        "false_positive_guidance": [
            "Zweryfikuj źródło reputacji, confidence i pierwotne pole zdarzenia.",
            "IOC może być współdzieloną infrastrukturą; dopasowanie nie potwierdza ataku.",
        ],
        "references": [],
    }


def unmapped_view() -> MappingView:
    catalog = metadata()
    definition = {
        "version": "intelligence-mapping-v1",
        "rule": rule_snapshot(),
        "techniques": [],
        "claim": "candidate_association",
    }
    return MappingView(
        status="unmapped",
        claim="candidate_association",
        confirmed_attack=False,
        catalogue_version=catalog.version,
        catalogue_hash=catalog.sha256,
        mapping_version="intelligence-mapping-v1",
        mapping_hash=hashlib.sha256(canonical_json(definition)).hexdigest(),
        techniques=[],
        reason="Reputacja IOC nie ustanawia techniki ATT&CK; brak mapowania.",
    )
