"""Extract typed observed IOCs only; source assertions are never inferred from raw text."""

from app.modules.intelligence.normalization import normalize_indicator, url_host
from app.modules.normalization.schemas import NormalizedSecurityEvent, canonical_ip

MAX_EXTRACTED_INDICATORS = 32


def extract_indicators(event: NormalizedSecurityEvent) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, observed: str | None, field: str) -> bool:
        if observed is None or len(result) >= MAX_EXTRACTED_INDICATORS:
            return False
        try:
            value = normalize_indicator(kind, observed)
        except ValueError:
            return False
        key = kind, value, field
        if key not in seen:
            seen.add(key)
            result.append(
                {"type": kind, "value": value, "field": field, "observed_value": observed}
            )
        return True

    for field, address in (
        ("source.ip", event.source.ip),
        ("destination.ip", event.destination.ip),
    ):
        if address is not None:
            add("ip", canonical_ip(address), field)
    if event.http is not None:
        for field, observed in (
            ("http.url", event.http.url),
            ("http.referrer", event.http.referrer),
        ):
            if add("url", observed, field):
                assert observed is not None
                host = url_host(observed)
                if not add("ip", host, field + ".host"):
                    add("domain", host, field + ".host")
    add("hash", event.process.hash, "process.hash")
    if event.file is not None:
        add("hash", event.file.hash, "file.hash")
    return result
