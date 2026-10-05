"""The alert proof budget includes pending contributors before loading full arrays."""

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from app.modules.entities import indexing
from app.modules.entities.schemas import IndexStatus


def test_pending_alerts_consume_total_proof_budget(monkeypatch) -> None:
    identifiers = [uuid4() for _ in range(3)]
    first = SimpleNamespace(id=identifiers[0])
    second = SimpleNamespace(id=identifiers[1])
    db = MagicMock()
    db.execute.side_effect = [
        None,
        MagicMock(all=lambda: []),
        MagicMock(
            all=lambda: [
                (identifiers[0], 99),
                (identifiers[1], 1),
                (identifiers[2], 1),
            ]
        ),
    ]
    db.get.side_effect = [first, second]
    db.scalar.side_effect = [0, 1]
    proof = [SimpleNamespace(event_id=uuid4()) for _ in range(100)]
    verified = MagicMock(side_effect=[proof[:99], proof[99:]])
    index_alert = MagicMock()
    monkeypatch.setattr(indexing, "verified_events", verified)
    monkeypatch.setattr(indexing, "index_alert", index_alert)
    monkeypatch.setattr(
        indexing,
        "global_index_status",
        lambda _: IndexStatus(
            pending_events=99,
            pending_alerts=2,
            complete=False,
        ),
    )
    monkeypatch.setattr(indexing, "append_audit", MagicMock())
    result = indexing.backfill(db, 100, actor_id=uuid4(), request_id="bounded")
    assert result.events == 0 and result.alerts == 1
    assert verified.call_count == db.get.call_count == 2
    index_alert.assert_called_once_with(db, second, ensure_existing_events=True)
    sql = str(db.execute.call_args_list[2].args[0])
    assert "SELECT a.id,CASE" in sql and "a.*" not in sql
