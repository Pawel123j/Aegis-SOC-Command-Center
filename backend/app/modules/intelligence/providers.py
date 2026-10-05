"""Read-only local provider adapter; external providers require a separate integration."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol

from app.modules.intelligence.normalization import (
    NORMALIZATION_VERSION,
    IndicatorType,
    normalize_indicator,
)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    id: str
    name: str
    kind: Literal["local", "online"]
    enabled: bool
    network_access: bool
    status: Literal["available", "disabled", "unconfigured"]
    description: str


LOCAL_PROVIDER = ProviderMetadata(
    id="local",
    name="Local IOC catalogue",
    kind="local",
    enabled=True,
    network_access=False,
    status="available",
    description="Versioned analyst-maintained IOC records stored locally. No external queries.",
)


class IntelligenceProvider(Protocol):
    def metadata(self) -> ProviderMetadata: ...

    def lookup(self, kind: IndicatorType, value: str) -> Sequence[Mapping[str, Any]]: ...


class LocalProvider:
    """Inject the caller's authorized, read-only repository; never invent matches."""

    def __init__(
        self,
        lookup: Callable[[IndicatorType, str], Sequence[Mapping[str, Any]]],
    ) -> None:
        self._lookup = lookup

    def metadata(self) -> ProviderMetadata:
        return LOCAL_PROVIDER

    def lookup(self, kind: IndicatorType, value: str) -> Sequence[Mapping[str, Any]]:
        canonical = normalize_indicator(kind, value)
        return tuple(MappingProxyType(dict(item)) for item in self._lookup(kind, canonical))


def providers_view() -> dict[str, Any]:
    return {"items": [asdict(LOCAL_PROVIDER)], "normalization_version": NORMALIZATION_VERSION}
