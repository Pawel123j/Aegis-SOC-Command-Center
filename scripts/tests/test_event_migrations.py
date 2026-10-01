"""The shipped ClickHouse migration and infrastructure review copy stay byte-identical."""

from pathlib import Path


def test_canonical_migration_matches_infrastructure_copy() -> None:
    root = Path(__file__).resolve().parents[2]
    canonical = root / "backend/app/modules/events/migrations"
    mirror = root / "infra/clickhouse/migrations"
    names = sorted(path.name for path in canonical.glob("*.sql"))
    assert names == sorted(path.name for path in mirror.glob("*.sql"))
    assert names
    for name in names:
        assert (canonical / name).read_bytes() == (mirror / name).read_bytes()
