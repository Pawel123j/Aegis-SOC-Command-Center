"""Real catalog authority, revision history, exact lookup and atomic local import."""

from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from .helper_intelligence import BASE, counts, create
from .helpers import Case, Login, migrate
from .test_initial_alerts import user

pytestmark = pytest.mark.integration


def read(principal: Login, path: str = "/iocs", **params: Any) -> dict[str, Any]:
    response = principal.client.get(BASE + path, params=params, headers=principal.authorization)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    return dict(response.json())


@pytest.mark.parametrize("role", ["admin", "soc_manager", "soc_analyst", "read_only"])
def test_every_read_role_can_lookup_local_catalog_with_truthful_provider_metadata(
    case: Case, admin: Login, role: str
) -> None:
    principal = admin if role == "admin" else user(case, admin, role)
    item = create(admin)
    before = counts(case)
    assert read(principal)["items"][0] == item
    provider = read(principal, "/providers")
    assert provider["items"][0]["enabled"] and not provider["items"][0]["network_access"]
    response = principal.client.post(
        BASE + "/lookup",
        json={"type": "domain", "value": "EXAMPLE.TEST."},
        headers=principal.authorization,
    )
    assert response.status_code == 200 and response.json()["item"] == item
    assert counts(case) == before


@pytest.mark.parametrize("role", ["soc_analyst", "read_only"])
def test_read_roles_cannot_publish_or_change_catalog(case: Case, admin: Login, role: str) -> None:
    principal = user(case, admin, role)
    item = create(admin)
    before = counts(case)
    responses = [
        principal.client.post(
            BASE + "/iocs",
            json={"type": "domain", "value": "other.test", "source": "local"},
            headers=principal.authorization,
        ),
        principal.client.patch(
            BASE + f"/iocs/{item['id']}",
            json={"active": False},
            headers={**principal.authorization, "If-Match": '"1"'},
        ),
        principal.client.post(
            BASE + "/import",
            json={"items": [{"type": "ip", "value": "192.0.2.1", "source": "local"}]},
            headers=principal.authorization,
        ),
    ]
    assert all(response.status_code == 403 for response in responses)
    assert counts(case)["ioc_revisions"] == before["ioc_revisions"]


def test_metadata_patch_is_append_only_with_preconditions_archive_and_noop(
    case: Case, admin: Login
) -> None:
    item = create(admin)
    path = BASE + f"/iocs/{item['id']}"
    assert (
        admin.client.patch(
            path, json={"reputation": "malicious"}, headers=admin.authorization
        ).status_code
        == 428
    )
    assert (
        admin.client.patch(
            path, json={"active": False}, headers={**admin.authorization, "If-Match": '"2"'}
        ).status_code
        == 412
    )
    changed = admin.client.patch(
        path,
        json={"reputation": "malicious", "confidence": 90, "active": False, "tags": ["reviewed"]},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert changed.status_code == 200, changed.text
    current = changed.json()
    assert current["version"] == current["revision"] == 2 and current["id"] == item["id"]
    assert changed.headers["etag"] == '"2"' and current["revision_id"] != item["revision_id"]
    history = read(admin, f"/iocs/{item['id']}/history")
    assert history["total"] == 2 and [row["revision"] for row in history["items"]] == [2, 1]
    assert history["items"][1]["document"]["active"] is True
    assert history["items"][1]["document_sha256"] == item["document_sha256"]
    before = counts(case)
    repeated = admin.client.patch(
        path, json={"active": False}, headers={**admin.authorization, "If-Match": '"2"'}
    )
    assert repeated.status_code == 200 and repeated.json() == current and counts(case) == before
    assert read(admin, active=True)["total"] == 0 and read(admin, active=False)["total"] == 1
    assert admin.client.delete(path, headers=admin.authorization).status_code == 405


def test_canonical_duplicate_is_exact_current_idempotence_and_changed_metadata_conflicts(
    case: Case, admin: Login
) -> None:
    item = create(admin, "EXAMPLE.TEST.")
    before = counts(case)
    body = {"type": "domain", "value": "example.test", "source": "Local test declaration"}
    same = admin.client.post(BASE + "/iocs", json=body, headers=admin.authorization)
    assert same.status_code == 200 and same.json() == item and counts(case) == before
    changed = admin.client.post(
        BASE + "/iocs", json={**body, "reputation": "malicious"}, headers=admin.authorization
    )
    assert changed.status_code == 409 and changed.json()["code"] == "ioc_exists"
    assert counts(case) == before


def test_import_is_bounded_atomic_and_rejects_duplicate_canonical_keys(
    case: Case, admin: Login
) -> None:
    original = create(admin)
    before = counts(case)
    duplicate = [
        {"type": "domain", "value": v, "source": "local"} for v in ("other.test", "OTHER.TEST.")
    ]
    response = admin.client.post(
        BASE + "/import", json={"items": duplicate}, headers=admin.authorization
    )
    assert response.status_code == 422 and response.json()["code"] == "ioc_import_duplicates"
    assert counts(case) == before
    conflict = [
        {"type": "domain", "value": "new.test", "source": "local"},
        {"type": "domain", "value": "example.test", "source": "changed"},
    ]
    response = admin.client.post(
        BASE + "/import", json={"items": conflict}, headers=admin.authorization
    )
    assert response.status_code == 409 and counts(case) == before
    values = [
        {"type": "ip", "value": "192.0.2.1", "source": "local"},
        {"type": "domain", "value": "example.test", "source": "Local test declaration"},
    ]
    response = admin.client.post(
        BASE + "/import", json={"items": values}, headers=admin.authorization
    )
    assert response.status_code == 200, response.text
    assert response.json()["created"] == response.json()["unchanged"] == 1
    assert response.json()["items"][1] == original
    assert counts(case)["ioc_identities"] == counts(case)["ioc_revisions"] == 2
    assert (
        admin.client.post(
            BASE + "/import", json={"items": []}, headers=admin.authorization
        ).status_code
        == 422
    )
    assert (
        admin.client.post(
            BASE + "/import", json={"items": values * 51}, headers=admin.authorization
        ).status_code
        == 422
    )


def test_list_and_history_have_exact_totals_signed_keyset_and_literal_filters(
    case: Case, admin: Login
) -> None:
    items = [create(admin, f"host{i}.test", description="literal_%") for i in range(3)]
    page = read(admin, limit=1, q="_%")
    assert page["total"] == 3 and page["limits"] == {
        "max_iocs": 1000,
        "max_revisions": 50,
        "max_import": 100,
    }
    seen = [page["items"][0]["id"]]
    while page["next_cursor"]:
        page = read(admin, limit=1, q="_%", cursor=page["next_cursor"])
        assert page["total"] == 3
        seen.append(page["items"][0]["id"])
    assert len(set(seen)) == len(seen) == 3
    assert read(admin, q="' OR 1=1 --")["total"] == 0
    item = items[0]
    response = admin.client.patch(
        BASE + f"/iocs/{item['id']}",
        json={"confidence": 80},
        headers={**admin.authorization, "If-Match": '"1"'},
    )
    assert response.status_code == 200, response.text
    first = read(admin, f"/iocs/{item['id']}/history", limit=1)
    assert first["total"] == 2 and first["next_cursor"]
    second = read(admin, f"/iocs/{item['id']}/history", limit=1, cursor=first["next_cursor"])
    assert (
        second["total"] == 2
        and second["next_cursor"] is None
        and second["items"][0]["revision"] == 1
    )


def test_lookup_miss_and_missing_detail_do_not_create_catalog_rows(
    case: Case, admin: Login
) -> None:
    before = counts(case)
    response = admin.client.post(
        BASE + "/lookup", json={"type": "ip", "value": "192.0.2.1"}, headers=admin.authorization
    )
    assert (
        response.status_code == 200
        and not response.json()["found"]
        and response.json()["item"] is None
    )
    assert (
        admin.client.get(BASE + f"/iocs/{uuid4()}", headers=admin.authorization).status_code == 404
    )
    assert counts(case) == before


def test_downgrade_refuses_nonempty_catalog_before_removing_seed(case: Case, admin: Login) -> None:
    item = create(admin)
    before = counts(case)
    with pytest.raises(DBAPIError) as rejected:
        migrate(case.database.owner, "0010_entities", downgrade=True)
    assert getattr(rejected.value.orig, "sqlstate", None) == "23514"
    assert "Intelligence history exists" in str(rejected.value)
    assert counts(case) == before and read(admin, f"/iocs/{item['id']}") == item
    with case.database.runtime.connect() as db:
        assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0011_intelligence"
        assert (
            db.scalar(
                text("SELECT enabled FROM rule_deployments WHERE id='ti:malicious-indicator'")
            )
            is True
        )


def test_empty_downgrade_and_reupgrade_preserve_previous_schema(case: Case, admin: Login) -> None:
    migrate(case.database.owner, "0010_entities", downgrade=True)
    with case.database.owner.connect() as db:
        assert db.scalar(text("SELECT to_regclass('public.ioc_identities')")) is None
        assert (
            db.scalar(
                text("SELECT count(*) FROM rule_deployments WHERE id='ti:malicious-indicator'")
            )
            == 0
        )
    migrate(case.database.owner)
    assert read(admin)["items"] == []
