"""Provider metadata and local lookup adapter never claim an external integration."""

from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from app.modules.intelligence.normalization import NORMALIZATION_VERSION, IndicatorType
from app.modules.intelligence.providers import (
    LOCAL_PROVIDER,
    IntelligenceProvider,
    LocalProvider,
    providers_view,
)


def test_provider_metadata_is_local_available_and_network_disabled() -> None:
    result = providers_view()
    assert result["normalization_version"] == NORMALIZATION_VERSION
    assert len(result["items"]) == 1
    item = result["items"][0]
    assert item["id"] == "local" and item["kind"] == "local"
    assert item["enabled"] is True and item["status"] == "available"
    assert item["network_access"] is False
    assert set(item) == {"id", "name", "kind", "enabled", "status", "network_access", "description"}


def test_metadata_is_frozen_and_response_copies_cannot_change_it() -> None:
    with pytest.raises(FrozenInstanceError):
        LOCAL_PROVIDER.network_access = True  # type: ignore[misc]
    result = providers_view()
    result["items"][0]["network_access"] = True
    assert providers_view()["items"][0]["network_access"] is False


def test_local_lookup_calls_only_injected_repository_with_canonical_indicator() -> None:
    seen: list[tuple[IndicatorType, str]] = []
    original = {"id": "local-record", "value": "example.com"}

    def repository(kind: IndicatorType, value: str) -> list[dict[str, Any]]:
        seen.append((kind, value))
        return [original]

    provider: IntelligenceProvider = LocalProvider(repository)
    result = provider.lookup("domain", "EXAMPLE.COM.")
    assert seen == [("domain", "example.com")]
    assert len(result) == 1 and result[0]["id"] == "local-record"
    assert provider.metadata() == LOCAL_PROVIDER
    with pytest.raises(TypeError):
        result[0]["value"] = "changed"  # type: ignore[index]
    assert original["value"] == "example.com"


def test_invalid_lookup_never_calls_repository() -> None:
    def forbidden_repository(kind: IndicatorType, value: str) -> list[dict[str, Any]]:
        raise AssertionError("Invalid indicators must not reach a provider")

    provider = LocalProvider(forbidden_repository)
    with pytest.raises(ValueError):
        provider.lookup("domain", "*.example.com")


def test_empty_repository_is_reported_as_empty_without_fabricating_reputation() -> None:
    provider = LocalProvider(lambda kind, value: [])
    assert provider.lookup("ip", "192.0.2.1") == ()
