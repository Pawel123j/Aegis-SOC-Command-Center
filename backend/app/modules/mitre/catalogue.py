"""Offline catalogue loading with a pinned digest and strict relationship validation."""

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.modules.mitre.schemas import CatalogueMeta, CatalogueView, TacticView, TechniqueView

CATALOGUE_SHA256 = "afc5aec04660aa0f1f2ed495247239002695574735a57133529803f08946a339"
CATALOGUE_VERSION = "19.2"
SOURCE_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
CATALOGUE_PATH = Path(__file__).parent / "data" / "enterprise-attack-19.2.json"


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Provenance(Frozen):
    domain: Literal["enterprise-attack"]
    attack_version: Literal["19.2"]
    release_tag: Literal["v19.2"]
    tag_object_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_url: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_published_at: AwareDatetime
    collection_id: str
    collection_version: Literal["19.2"]
    collection_modified: AwareDatetime
    fetched_at: AwareDatetime


class Entry(Frozen):
    id: str
    stix_id: str
    name: str = Field(min_length=1, max_length=256)
    url: str
    version: str = Field(min_length=1, max_length=32)
    modified: AwareDatetime
    revoked: bool = Field(strict=True)
    deprecated: bool = Field(strict=True)

    @property
    def active(self) -> bool:
        return not self.revoked and not self.deprecated


class Tactic(Entry):
    id: str = Field(pattern=r"^TA[0-9]{4}$")
    short_name: str = Field(pattern=r"^[a-z]+(?:-[a-z]+)*$")


class Technique(Entry):
    id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    is_subtechnique: bool = Field(strict=True)
    parent_id: str | None
    tactic_ids: tuple[str, ...] = Field(max_length=30)
    platforms: tuple[str, ...] = Field(max_length=30)


def _stix(value: str, prefix: str) -> None:
    if not value.startswith(prefix + "--"):
        raise ValueError("invalid STIX object type")
    UUID(value.removeprefix(prefix + "--"))


class Catalogue(Frozen):
    schema_version: Literal[1]
    provenance: Provenance
    tactics: tuple[Tactic, ...] = Field(min_length=1, max_length=30)
    techniques: tuple[Technique, ...] = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        source = self.provenance
        expected_source = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            f"{SOURCE_COMMIT}/enterprise-attack/enterprise-attack-19.2.json"
        )
        if source.source_commit != SOURCE_COMMIT or source.source_url != expected_source:
            raise ValueError("catalogue provenance does not match pinned release")
        _stix(source.collection_id, "x-mitre-collection")
        tactics = {item.id: item for item in self.tactics}
        techniques = {item.id: item for item in self.techniques}
        entries = (*self.tactics, *self.techniques)
        if (
            len(tactics) != len(self.tactics)
            or len(techniques) != len(self.techniques)
            or len({entry.stix_id for entry in entries}) != len(entries)
            or len({item.short_name for item in self.tactics}) != len(self.tactics)
        ):
            raise ValueError("duplicate catalogue identity")
        for tactic in self.tactics:
            _stix(tactic.stix_id, "x-mitre-tactic")
            if tactic.url != f"https://attack.mitre.org/tactics/{tactic.id}":
                raise ValueError("invalid canonical tactic URL")
        for technique in self.techniques:
            _stix(technique.stix_id, "attack-pattern")
            if (
                technique.url
                != "https://attack.mitre.org/techniques/" + technique.id.replace(".", "/")
                or technique.is_subtechnique != ("." in technique.id)
                or len(set(technique.tactic_ids)) != len(technique.tactic_ids)
                or any(identity not in tactics for identity in technique.tactic_ids)
            ):
                raise ValueError("invalid technique or tactic relationship")
            if technique.active and (
                not technique.tactic_ids
                or any(not tactics[identity].active for identity in technique.tactic_ids)
            ):
                raise ValueError("active technique needs active tactic relationships")
            if technique.parent_id is not None:
                parent = techniques.get(technique.parent_id)
                if (
                    not technique.is_subtechnique
                    or parent is None
                    or parent.is_subtechnique
                    or technique.id.split(".")[0] != parent.id
                    or (technique.active and not parent.active)
                ):
                    raise ValueError("invalid subtechnique parent")
            elif technique.is_subtechnique and technique.active:
                raise ValueError("active subtechnique needs an explicit parent relationship")
        return self

    def technique(self, identity: str) -> Technique:
        match = next((item for item in self.techniques if item.id == identity), None)
        if match is None or not match.active:
            raise ValueError("unknown or retired ATT&CK technique")
        return match

    def tactic(self, identity: str) -> Tactic:
        match = next((item for item in self.tactics if item.id == identity), None)
        if match is None or not match.active:
            raise ValueError("unknown or retired ATT&CK tactic")
        return match


def validate_document(document: Any) -> Catalogue:
    return Catalogue.model_validate(document)


def read_catalogue(path: Path, expected_hash: str = CATALOGUE_SHA256) -> Catalogue:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("invalid catalogue digest")
    raw = path.read_bytes()
    if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("catalogue integrity mismatch")
    return validate_document(json.loads(raw))


@lru_cache(maxsize=1)
def catalogue() -> Catalogue:
    return read_catalogue(CATALOGUE_PATH)


def metadata() -> CatalogueMeta:
    data = catalogue()
    return CatalogueMeta(
        version=CATALOGUE_VERSION,
        sha256=CATALOGUE_SHA256,
        source_url=data.provenance.source_url,
        source_sha256=data.provenance.source_sha256,
        source_commit=data.provenance.source_commit,
        attribution="© 2026 The MITRE Corporation. This work is reproduced and distributed "
        "with the permission of The MITRE Corporation.",
        license_url=f"https://github.com/mitre-attack/attack-stix-data/blob/{SOURCE_COMMIT}/LICENSE.txt",
        tactics_count=sum(item.active for item in data.tactics),
        techniques_count=sum(item.active for item in data.techniques),
    )


def catalogue_view() -> CatalogueView:
    data = catalogue()
    return CatalogueView(
        catalogue=metadata(),
        tactics=[
            TacticView(id=item.id, name=item.name, url=item.url, short_name=item.short_name)
            for item in data.tactics
            if item.active
        ],
        techniques=[
            TechniqueView(
                id=item.id,
                name=item.name,
                url=item.url,
                parent_id=item.parent_id,
                tactic_ids=list(item.tactic_ids),
                is_subtechnique=item.is_subtechnique,
            )
            for item in data.techniques
            if item.active
        ],
    )
