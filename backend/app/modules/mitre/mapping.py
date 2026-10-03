"""Controlled catalogue associations without reinterpreting existing frozen detections."""

import hashlib
from collections.abc import Iterable

from app.modules.correlation.builtin import BUILTIN_RULES as CORRELATION_RULES
from app.modules.detections.builtin import BUILTIN_RULES
from app.modules.ingestion.schemas import canonical_json
from app.modules.mitre.catalogue import CATALOGUE_SHA256, CATALOGUE_VERSION, catalogue
from app.modules.mitre.schemas import MappingView, Reference, TechniqueMapping

MAPPING_VERSION = "mitre-mapping-v1"


def definitions() -> dict[str, tuple[str, ...]]:
    return {
        **{rule.id: rule.mitre for rule in BUILTIN_RULES},
        **{rule.id: tuple(rule.mitre) for rule in CORRELATION_RULES},
    }


def policy_hash() -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "version": MAPPING_VERSION,
                "catalogue_hash": CATALOGUE_SHA256,
                "claim": "candidate_association",
                "tactics": "all-active-official-technique-relationships",
                "rules": definitions(),
            }
        )
    ).hexdigest()


def associate(technique_ids: Iterable[str]) -> list[TechniqueMapping]:
    data = catalogue()
    identities = list(technique_ids)
    if len(identities) > 20 or len(set(identities)) != len(identities):
        raise ValueError("bounded unique techniques are required")
    results = []
    for identity in sorted(identities):
        technique = data.technique(identity)
        tactics = [data.tactic(tactic_id) for tactic_id in technique.tactic_ids]
        results.append(
            TechniqueMapping(
                id=technique.id,
                name=technique.name,
                url=technique.url,
                tactics=[Reference(id=item.id, name=item.name, url=item.url) for item in tactics],
            )
        )
    return results


def validate_pair(technique_id: str, tactic_id: str) -> None:
    technique = catalogue().technique(technique_id)
    catalogue().tactic(tactic_id)
    if tactic_id not in technique.tactic_ids:
        raise ValueError("technique does not belong to tactic in pinned catalogue")


def rule_mapping(rule_id: str) -> MappingView:
    supported = definitions()
    if rule_id not in supported:
        raise ValueError("unknown MITRE mapping rule")
    techniques = associate(supported[rule_id])
    return MappingView(
        status="mapped" if techniques else "unmapped",
        catalogue_version=CATALOGUE_VERSION,
        catalogue_hash=CATALOGUE_SHA256,
        mapping_version=MAPPING_VERSION,
        mapping_hash=policy_hash(),
        techniques=techniques,
        reason=(
            "Catalogue associations describe candidate behaviours, not confirmed attack, "
            "success or attacker intent."
            if techniques
            else "The observed root session does not establish sudo abuse; no technique assigned."
        ),
    )


def legacy_mapping() -> MappingView:
    return MappingView(
        status="legacy_unmapped",
        catalogue_version=None,
        catalogue_hash=None,
        mapping_version=None,
        mapping_hash=None,
        techniques=[],
        reason="No frozen MITRE association was recorded when this alert was created.",
    )
