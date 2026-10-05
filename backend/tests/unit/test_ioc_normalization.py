"""Canonical IOC keys reject false joins and preserve significant URL distinctions."""

from typing import Any

import pytest

from app.modules.intelligence.normalization import (
    MAX_INDICATOR_LENGTH,
    NORMALIZATION_VERSION,
    normalize_indicator,
    url_host,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.0.2.1", "192.0.2.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("::1", "::1"),
        ("::", "::"),
        ("::ffff:192.0.2.1", "::ffff:c000:201"),
        ("::FFFF:C000:0201", "::ffff:c000:201"),
    ],
)
def test_ip_canonical_text_and_ipv6_family_are_stable(value: str, expected: str) -> None:
    assert normalize_indicator("ip", value) == expected
    assert normalize_indicator("ip", expected) == expected


@pytest.mark.parametrize(
    "value",
    [
        "192.168.001.1",
        "192.0.2.1/32",
        "2001:db8::/64",
        "fe80::1%eth0",
        "[2001:db8::1]",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "192.0.2.1:80",
        "example.com",
        "2001:db8:::1",
        "999.1.2.3",
    ],
)
def test_ip_rejects_ambiguous_forms_networks_and_zones(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_indicator("ip", value)


def test_mapped_ipv6_does_not_join_ipv4() -> None:
    assert normalize_indicator("ip", "::ffff:192.0.2.1") != normalize_indicator("ip", "192.0.2.1")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("EXAMPLE.COM", "example.com"),
        ("Example.Com.", "example.com"),
        ("example.com。", "example.com"),
        ("BÜCHER.Example.", "xn--bcher-kva.example"),
        ("xn--bcher-kva.Example", "xn--bcher-kva.example"),
        ("faß.de", "xn--fa-hia.de"),
        ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
        ("xn--r8jz45g.xn--zckzah", "xn--r8jz45g.xn--zckzah"),
        ("ｅxample.com", "example.com"),
        ("one.two.example", "one.two.example"),
    ],
)
def test_domains_use_idna2008_nontransitional_exact_fqdn(value: str, expected: str) -> None:
    assert normalize_indicator("domain", value) == expected
    assert normalize_indicator("domain", expected) == expected


def test_domain_compatibility_does_not_erase_sharp_s_or_subdomain() -> None:
    assert normalize_indicator("domain", "faß.de") != normalize_indicator("domain", "fass.de")
    assert normalize_indicator("domain", "a.example.com") != normalize_indicator(
        "domain", "example.com"
    )
    assert normalize_indicator("domain", "раypal.com") != normalize_indicator(
        "domain", "paypal.com"
    )


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "single",
        ".example.com",
        "example..com",
        "example.com..",
        ".",
        "*.example.com",
        "_service.example.com",
        "http://example.com",
        "example.com/path",
        "example.com:443",
        "user@example.com",
        "example.com?x=1",
        "example.com#fragment",
        "[::1]",
        "::1",
        "192.0.2.1",
        "192.0.2.1.",
        "１９２。０。２。１",
        "127.1",
        "-example.com",
        "example-.com",
        "xn--.example",
        "💥.example",
        "ex%61mple.com",
        "example.123",
        "a" * 64 + ".example",
        ".".join(["a" * 63] * 3 + ["b" * 62]),
    ],
)
def test_domains_reject_paths_ips_wildcards_and_invalid_dns_labels(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_indicator("domain", value)


def test_domain_dns_length_boundary() -> None:
    value = ".".join(["a" * 63] * 3 + ["b" * 61])
    assert len(value) == 253
    assert normalize_indicator("domain", value + ".") == value


@pytest.mark.parametrize(
    "value,expected",
    [
        ("HTTP://EXAMPLE.COM", "http://example.com/"),
        ("https://BÜCHER.Example.:443/A?X=Y#Case", "https://xn--bcher-kva.example/A?X=Y#Case"),
        ("http://example.com:080/a", "http://example.com/a"),
        ("https://example.com:80/", "https://example.com:80/"),
        ("http://example.com:8080/", "http://example.com:8080/"),
        ("http://192.0.2.1:80", "http://192.0.2.1/"),
        ("HTTP://[2001:0DB8:0:0:0:0:0:1]:80/A", "http://[2001:db8::1]/A"),
        ("https://[::ffff:192.0.2.1]:443", "https://[::ffff:c000:201]/"),
        ("http://example.com/a/../b", "http://example.com/a/../b"),
        ("http://example.com/%2e%2f?A=%7e", "http://example.com/%2E%2F?A=%7E"),
        ("http://example.com?", "http://example.com/?"),
        ("http://example.com#", "http://example.com/#"),
        ("http://example.com?#", "http://example.com/?#"),
        ("http://example.com/#a?b", "http://example.com/#a?b"),
        ("http://example.com/a?b=2&a=1&a=3", "http://example.com/a?b=2&a=1&a=3"),
        ("http://example.com/%40user", "http://example.com/%40user"),
        ("http://faß.de/żółć", "http://xn--fa-hia.de/żółć"),
    ],
)
def test_urls_preserve_route_meaning_and_canonicalize_authority(value: str, expected: str) -> None:
    assert normalize_indicator("url", value) == expected
    assert normalize_indicator("url", expected) == expected


@pytest.mark.parametrize(
    "left,right",
    [
        ("http://example.com/A", "http://example.com/a"),
        ("http://example.com/?X=Y", "http://example.com/?x=y"),
        ("http://example.com/?a=1&b=2", "http://example.com/?b=2&a=1"),
        ("http://example.com/a/../b", "http://example.com/b"),
        ("http://example.com/%2F", "http://example.com//"),
        ("http://example.com/%41", "http://example.com/A"),
        ("http://example.com/", "http://example.com/?"),
        ("http://example.com/", "http://example.com/#"),
        ("http://example.com/#route1", "http://example.com/#route2"),
    ],
)
def test_url_inequivalent_route_values_do_not_join(left: str, right: str) -> None:
    assert normalize_indicator("url", left) != normalize_indicator("url", right)


@pytest.mark.parametrize(
    "value",
    [
        "example.com/path",
        "/relative",
        "//example.com/",
        "ftp://example.com/file",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https:///path",
        "http://",
        "http://user@example.com/",
        "http://user:pass@example.com/",
        "http://@example.com/",
        "http://user%40name@example.com/",
        "http://example.com:/",
        "http://example.com:65536/",
        "http://example.com:-1/",
        "http://example.com:abc/",
        "http://example.com:000080/",
        "http://example.com:１２/",
        "http://127.1/",
        "http://2130706433/",
        "http://localhost/",
        "http://2001:db8::1/",
        "http://[::1]evil/",
        "http://[::1]:/",
        "http://[fe80::1%eth0]/",
        "http://[v1.host]/",
        "http://example.com\\@evil.example/",
        "http://example.com/%",
        "http://example.com/%1",
        "http://example.com/%xz",
        "http://example.com/?x=%gg",
        "http://example.com/#%xy",
        "http://%65xample.com/",
        "http://*.example.com/",
    ],
)
def test_urls_reject_ambiguous_authorities_credentials_controls_and_bad_percent(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_indicator("url", value)


def test_url_host_preserves_observed_host_including_case_and_idna() -> None:
    assert url_host("HTTPS://BÜCHER.Example.:443/a") == "BÜCHER.Example."
    assert url_host("http://[2001:0DB8::1]:80/") == "2001:0DB8::1"


@pytest.mark.parametrize(
    "algorithm,length", [("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)]
)
@pytest.mark.parametrize("prefix", ["", "colon", "equals", "hyphen"])
def test_hashes_use_explicit_algorithm_and_lowercase_hex(
    algorithm: str,
    length: int,
    prefix: str,
) -> None:
    digest = "AB" * (length // 2)
    name = algorithm.replace("sha", "SHA-") if prefix == "hyphen" else algorithm.upper()
    value = digest if prefix == "" else name + ("=" if prefix == "equals" else ":") + digest
    assert normalize_indicator("hash", value) == algorithm + ":" + digest.lower()


@pytest.mark.parametrize(
    "value",
    [
        "aa" * 10,
        "aa" * 28,
        "sha224:" + "aa" * 28,
        "sha256:" + "aa" * 16,
        "md5:" + "aa" * 32,
        "SHA256=" + "gg" * 32,
        "aa" * 32 + "," + "bb" * 16,
        "SHA256=" + "aa" * 32 + ",MD5=" + "bb" * 16,
        "sha256::" + "aa" * 32,
        "sha256:=" + "aa" * 32,
        "sha256:",
        "s-h-a-2-5-6:" + "aa" * 32,
    ],
)
def test_hashes_reject_lists_length_mismatches_and_unknown_algorithms(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_indicator("hash", value)


@pytest.mark.parametrize("kind", ["ip", "domain", "url", "hash"])
@pytest.mark.parametrize("value", ["", " ", "x\x00y", "x\ty", "x\ny", "x\ry", "x\x7fy", "x\u200fy"])
def test_each_type_rejects_empty_text_whitespace_and_control_characters(
    kind: str, value: str
) -> None:
    with pytest.raises(ValueError):
        normalize_indicator(kind, value)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("unknown", "example.com"),
        ("IP", "192.0.2.1"),
        (None, "example.com"),
        ("ip", None),
        ("ip", 2130706433),
        ("ip", True),
    ],
)
def test_type_and_value_are_not_silently_coerced(kind: Any, value: Any) -> None:
    with pytest.raises(ValueError):
        normalize_indicator(kind, value)


def test_canonical_url_length_boundary_and_sanitized_error() -> None:
    prefix = "http://example.com/"
    value = prefix + "a" * (MAX_INDICATOR_LENGTH - len(prefix))
    assert len(normalize_indicator("url", value)) == MAX_INDICATOR_LENGTH
    with pytest.raises(ValueError) as rejected:
        normalize_indicator("url", value + "PRIVATE")
    assert "PRIVATE" not in str(rejected.value)
    assert NORMALIZATION_VERSION == "ioc-normalization-v1"
