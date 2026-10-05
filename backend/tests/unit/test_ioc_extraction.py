"""Typed-field extraction preserves evidence roles and avoids guessing from log text."""

from copy import deepcopy
from typing import Any
from uuid import UUID

import pytest

from app.modules.intelligence import extraction
from app.modules.intelligence.extraction import MAX_EXTRACTED_INDICATORS, extract_indicators
from app.modules.normalization.schemas import NormalizedSecurityEvent


def event(**values: Any) -> NormalizedSecurityEvent:
    document = {
        "event_id": str(UUID(int=1)),
        "source_id": str(UUID(int=2)),
        "dataset_id": str(UUID(int=3)),
        "run_id": str(UUID(int=0)),
        "mode": "live",
        "timestamp": "2026-10-05T08:00:00Z",
        "received_at": "2026-10-05T08:00:01Z",
        "processed_at": "2026-10-05T08:00:02Z",
        "source": {"name": "Source", "type": "generic_json"},
        "raw_event": {},
        "raw_sha256": "ab" * 32,
    }
    document.update(values)
    return NormalizedSecurityEvent.model_validate(document)


def test_all_typed_ioc_fields_have_distinct_evidence_references() -> None:
    source = event(
        source={"name": "Source", "type": "generic_json", "ip": "192.0.2.1"},
        destination={"ip": "192.0.2.1"},
        http={"url": "https://BÜCHER.Example.:443/A#X", "referrer": "http://[::ffff:192.0.2.1]/"},
        process={"hash": "SHA256=" + "AB" * 32},
        file={"hash": "ab" * 16},
    )
    before = deepcopy(source.model_dump(mode="json"))
    result = extract_indicators(source)
    assert len(result) == 8 < MAX_EXTRACTED_INDICATORS
    assert {(item["type"], item["field"]) for item in result} == {
        ("ip", "source.ip"),
        ("ip", "destination.ip"),
        ("url", "http.url"),
        ("domain", "http.url.host"),
        ("url", "http.referrer"),
        ("ip", "http.referrer.host"),
        ("hash", "process.hash"),
        ("hash", "file.hash"),
    }
    domain = next(item for item in result if item["type"] == "domain")
    assert (
        domain["value"] == "xn--bcher-kva.example" and domain["observed_value"] == "BÜCHER.Example."
    )
    assert source.model_dump(mode="json") == before
    assert result == extract_indicators(source)


def test_empty_observation_has_no_synthetic_indicators() -> None:
    assert extract_indicators(event()) == []


def test_does_not_scan_raw_commands_host_names_user_agents_or_extensions() -> None:
    source = event(
        host={"name": "bad.example"},
        user={"name": "bad.example"},
        process={
            "command_line": "curl https://bad.example/a; ping 192.0.2.1",
            "name": "bad.example",
        },
        file={"name": "bad.example", "path": "https://bad.example/file"},
        raw_event={"network.domain": "bad.example", "hash": "ab" * 32, "ip": "192.0.2.1"},
        extensions={"network": {"domain": "bad.example"}},
        http={"user_agent": "https://bad.example"},
    )
    assert extract_indicators(source) == []


@pytest.mark.parametrize(
    "http",
    [
        {"url": "/relative", "referrer": "-"},
        {"url": "https://user:password@bad.example/"},
        {"url": "http://localhost/"},
        {"url": "http://bad.example/%zz"},
    ],
)
def test_invalid_http_field_does_not_produce_partial_host_matches(http: dict[str, str]) -> None:
    assert extract_indicators(event(http=http)) == []


def test_invalid_hash_field_does_not_suppress_valid_sibling() -> None:
    result = extract_indicators(event(process={"hash": "not-a-hash"}, file={"hash": "AB" * 32}))
    assert result == [
        {
            "type": "hash",
            "value": "sha256:" + "ab" * 32,
            "field": "file.hash",
            "observed_value": "AB" * 32,
        }
    ]


def test_relative_referrer_does_not_suppress_absolute_request_url() -> None:
    result = extract_indicators(event(http={"url": "http://example.com/A", "referrer": "/other"}))
    assert {(row["type"], row["field"]) for row in result} == {
        ("url", "http.url"),
        ("domain", "http.url.host"),
    }


def test_long_original_url_is_preserved_when_canonical_identity_fits() -> None:
    canonical = "http://example.com/" + "a" * (2048 - len("http://example.com/"))
    observed = "HTTP://EXAMPLE.COM:080/" + "a" * (2048 - len("http://example.com/"))
    assert len(observed) == 2052 and len(canonical) == 2048
    result = extract_indicators(event(http={"url": observed}))
    assert result == [
        {"type": "url", "value": canonical, "field": "http.url", "observed_value": observed},
        {
            "type": "domain",
            "value": "example.com",
            "field": "http.url.host",
            "observed_value": "EXAMPLE.COM",
        },
    ]


def test_ip_url_hosts_are_ip_and_never_domain_indicators() -> None:
    result = extract_indicators(
        event(http={"url": "http://192.0.2.1/", "referrer": "https://[2001:DB8::1]/"})
    )
    assert all(row["type"] != "domain" for row in result)
    hosts = {row["field"]: row["value"] for row in result if row["type"] == "ip"}
    assert hosts == {"http.url.host": "192.0.2.1", "http.referrer.host": "2001:db8::1"}


def test_ipv6_zone_in_typed_source_is_not_an_ioc() -> None:
    source = event(source={"name": "Source", "type": "generic_json", "ip": "fe80::1%eth0"})
    assert extract_indicators(source) == []


def test_same_value_in_multiple_fields_retains_each_evidence_location() -> None:
    source = event(
        http={"url": "http://example.com/", "referrer": "http://example.com/"},
        process={"hash": "ab" * 32},
        file={"hash": "AB" * 32},
    )
    result = extract_indicators(source)
    assert len(result) == 6
    assert len({(row["type"], row["value"], row["field"]) for row in result}) == len(result)


def test_explicit_extraction_budget_is_applied_even_if_future_fields_are_added(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extraction, "MAX_EXTRACTED_INDICATORS", 1)
    source = event(
        source={"name": "Source", "type": "generic_json", "ip": "192.0.2.1"},
        destination={"ip": "192.0.2.2"},
        http={"url": "http://example.com/"},
    )
    result = extract_indicators(source)
    assert len(result) == 1 and result[0]["field"] == "source.ip"
