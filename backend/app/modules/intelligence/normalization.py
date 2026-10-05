"""Conservative IOC identity normalization; no DNS, HTTP or provider lookups."""

import re
import unicodedata
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal
from urllib.parse import urlsplit

import idna

from app.modules.normalization.schemas import canonical_ip

IndicatorType = Literal["ip", "domain", "url", "hash"]
NORMALIZATION_VERSION = "ioc-normalization-v1"
MAX_INDICATOR_LENGTH = 2048
MAX_OBSERVED_INPUT_LENGTH = 8192
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_BAD_PERCENT = re.compile(r"%(?![a-fA-F0-9]{2})")
_PERCENT = re.compile(r"%[a-fA-F0-9]{2}")
_HEX = re.compile(r"[a-fA-F0-9]+\Z", re.ASCII)
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
_HASH_ALIASES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha512": "sha512",
    "sha-512": "sha512",
}


def _text(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_OBSERVED_INPUT_LENGTH
        or any(char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)
    ):
        raise ValueError("invalid_indicator_text")
    return value


def _ip(value: str) -> str:
    if any(char in value for char in "%/[]"):
        raise ValueError("invalid_ip_indicator")
    try:
        return canonical_ip(ip_address(value))
    except ValueError:
        raise ValueError("invalid_ip_indicator") from None


def _domain(value: str) -> str:
    if not value or any(char in value for char in "/\\:@?#%*[]_"):
        raise ValueError("invalid_domain_indicator")
    try:
        ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("ip_is_not_domain_indicator")
    try:
        result = idna.encode(value, uts46=True, transitional=False, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        raise ValueError("invalid_domain_indicator") from None
    result = result.removesuffix(".")
    labels = result.split(".")
    if (
        len(result) > 253
        or len(labels) < 2
        or labels[-1].isdigit()
        or any(_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise ValueError("invalid_domain_indicator")
    # Reject IP strings also after Unicode compatibility mapping.
    try:
        ip_address(result)
    except ValueError:
        return result
    raise ValueError("ip_is_not_domain_indicator")


def url_host(value: str) -> str:
    """Return the originally observed authority host from an accepted URL."""
    normalized = normalize_indicator("url", value)
    assert normalized
    authority = urlsplit(value).netloc
    if authority.startswith("["):
        return authority[1 : authority.index("]")]
    return authority.rsplit(":", 1)[0] if ":" in authority else authority


def _url(value: str) -> str:
    if "\\" in value or _BAD_PERCENT.search(value):
        raise ValueError("invalid_url_indicator")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ValueError("invalid_url_indicator") from None
    scheme = parts.scheme.lower()
    authority = parts.netloc
    if scheme not in {"http", "https"} or not authority or "@" in authority:
        raise ValueError("invalid_url_indicator")
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise ValueError("invalid_url_indicator")
        host, suffix = authority[1:closing], authority[closing + 1 :]
        try:
            address = ip_address(host)
        except ValueError:
            raise ValueError("invalid_url_indicator") from None
        if not isinstance(address, IPv6Address) or "%" in host:
            raise ValueError("invalid_url_indicator")
        host_key = f"[{canonical_ip(address)}]"
    else:
        if authority.count(":") > 1:
            raise ValueError("invalid_url_indicator")
        host, delimiter, port = authority.partition(":")
        suffix = delimiter + port
        try:
            address = ip_address(host)
        except ValueError:
            host_key = _domain(host)
        else:
            if not isinstance(address, IPv4Address):
                raise ValueError("invalid_url_indicator")
            host_key = canonical_ip(address)
    if suffix:
        digits = suffix[1:]
        if (
            not suffix.startswith(":")
            or not digits
            or len(digits) > 5
            or not digits.isascii()
            or not digits.isdecimal()
        ):
            raise ValueError("invalid_url_indicator")
        port_number = int(digits)
        if port_number > 65535:
            raise ValueError("invalid_url_indicator")
        if port_number != (80 if scheme == "http" else 443):
            host_key += f":{port_number}"
    result = f"{scheme}://{host_key}{parts.path or '/'}"
    # urllib reconstruction drops explicit empty delimiters. Preserve them and
    # fragments: application routes may assign significance to either.
    before_fragment = value.split("#", 1)[0]
    if "?" in before_fragment:
        result += "?" + parts.query
    if "#" in value:
        result += "#" + parts.fragment
    return _PERCENT.sub(lambda match: match[0].upper(), result)


def _hash(value: str) -> str:
    algorithm = None
    digest = value
    separators = [char for char in (":", "=") if char in value]
    if separators:
        if len(separators) != 1 or value.count(separators[0]) != 1:
            raise ValueError("invalid_hash_indicator")
        prefix, digest = value.split(separators[0])
        algorithm = _HASH_ALIASES.get(prefix.lower())
        if algorithm is None:
            raise ValueError("unsupported_hash_algorithm")
    if not digest or _HEX.fullmatch(digest) is None:
        raise ValueError("invalid_hash_indicator")
    if algorithm is None:
        algorithm = next(
            (name for name, length in _HASH_LENGTHS.items() if len(digest) == length), None
        )
    if algorithm is None or len(digest) != _HASH_LENGTHS[algorithm]:
        raise ValueError("invalid_hash_indicator")
    return f"{algorithm}:{digest.lower()}"


def normalize_indicator(kind: str, value: str) -> str:
    """Return one bounded canonical key or a sanitized ValueError."""
    value = _text(value)
    normalizers = {"ip": _ip, "domain": _domain, "url": _url, "hash": _hash}
    if not isinstance(kind, str) or kind not in normalizers:
        raise ValueError("unsupported_indicator_type")
    result = normalizers[kind](value)
    if len(result) > MAX_INDICATOR_LENGTH:
        raise ValueError("indicator_too_long")
    return result
