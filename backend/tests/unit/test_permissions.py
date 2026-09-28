"""Security boundaries are explicit, including unknown and future permissions."""

import pytest

from app.core.permissions import ROLE_PERMISSIONS, Permission, Role, has_permission, permissions_for


@pytest.mark.parametrize("permission", list(Permission))
def test_administrator_has_all_declared_permissions(permission: Permission) -> None:
    assert has_permission(Role.ADMIN, permission)


@pytest.mark.parametrize("role", [Role.SOC_MANAGER, Role.SOC_ANALYST, Role.READ_ONLY])
@pytest.mark.parametrize(
    "permission",
    [
        Permission.USERS_READ,
        Permission.USERS_MANAGE,
        Permission.SYSTEM_MANAGE,
        Permission.SOURCES_MANAGE,
    ],
)
def test_non_administrators_cannot_control_identity_or_system(
    role: Role, permission: Permission
) -> None:
    assert not has_permission(role, permission)


@pytest.mark.parametrize(
    ("permission", "manager", "analyst", "reader"),
    [
        (Permission.AUDIT_READ, True, False, False),
        (Permission.SYSTEM_READ, True, False, False),
        (Permission.EVENTS_READ, True, True, True),
        (Permission.ALERTS_READ, True, True, True),
        (Permission.ALERTS_MANAGE, True, True, False),
        (Permission.INCIDENTS_READ, True, True, True),
        (Permission.INCIDENTS_EDIT, True, True, False),
        (Permission.INCIDENTS_ASSIGN_SELF, True, True, False),
        (Permission.INCIDENTS_ASSIGN_ANY, True, False, False),
        (Permission.INCIDENTS_CLOSE, True, True, False),
        (Permission.INCIDENTS_REOPEN, True, False, False),
        (Permission.HUNT_QUERY, True, True, True),
        (Permission.HUNT_SAVE, True, True, False),
        (Permission.DETECTIONS_READ, True, True, True),
        (Permission.DETECTIONS_DRAFT, True, True, False),
        (Permission.DETECTIONS_TEST, True, True, False),
        (Permission.DETECTIONS_PUBLISH, True, False, False),
        (Permission.DETECTIONS_IMPORT, True, False, False),
        (Permission.INTELLIGENCE_READ, True, True, True),
        (Permission.INTELLIGENCE_PROPOSE, True, True, False),
        (Permission.INTELLIGENCE_MANAGE, True, False, False),
        (Permission.PLAYBOOKS_READ, True, True, True),
        (Permission.PLAYBOOKS_MANAGE, True, False, False),
        (Permission.PLAYBOOKS_RUN, True, True, False),
        (Permission.DEMO_RUN, True, False, False),
        (Permission.REPORTS_READ, True, True, True),
    ],
)
def test_operational_role_matrix(
    permission: Permission, manager: bool, analyst: bool, reader: bool
) -> None:
    assert has_permission(Role.SOC_MANAGER, permission) is manager
    assert has_permission(Role.SOC_ANALYST, permission) is analyst
    assert has_permission(Role.READ_ONLY, permission) is reader


@pytest.mark.parametrize("role", ["", "Admin", "superadmin", "admin ", "unknown"])
def test_unknown_roles_fail_closed(role: str) -> None:
    assert permissions_for(role) == frozenset()
    assert not has_permission(role, Permission.EVENTS_READ)


def test_unknown_permissions_fail_closed_even_for_admin() -> None:
    assert not has_permission(Role.ADMIN, "users:destroy_everything")


def test_role_map_and_capability_sets_cannot_be_mutated() -> None:
    assert set(ROLE_PERMISSIONS) == set(Role)
    assert all(isinstance(value, frozenset) for value in ROLE_PERMISSIONS.values())
    with pytest.raises(TypeError):
        ROLE_PERMISSIONS[Role.READ_ONLY] = frozenset(Permission)  # type: ignore[index]
