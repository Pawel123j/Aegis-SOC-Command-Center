"""Explicit role capabilities for one SOC organization; unknown roles fail closed."""

from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    ADMIN = "admin"
    SOC_MANAGER = "soc_manager"
    SOC_ANALYST = "soc_analyst"
    READ_ONLY = "read_only"


class Permission(StrEnum):
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    SYSTEM_READ = "system:read"
    SYSTEM_MANAGE = "system:manage"
    SOURCES_MANAGE = "sources:manage"
    EVENTS_READ = "events:read"
    ALERTS_READ = "alerts:read"
    ALERTS_MANAGE = "alerts:manage"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_EDIT = "incidents:edit"
    INCIDENTS_ASSIGN_SELF = "incidents:assign_self"
    INCIDENTS_ASSIGN_ANY = "incidents:assign_any"
    INCIDENTS_CLOSE = "incidents:close"
    INCIDENTS_REOPEN = "incidents:reopen"
    HUNT_QUERY = "hunt:query"
    HUNT_SAVE = "hunt:save"
    DETECTIONS_READ = "detections:read"
    DETECTIONS_DRAFT = "detections:draft"
    DETECTIONS_TEST = "detections:test"
    DETECTIONS_PUBLISH = "detections:publish"
    DETECTIONS_IMPORT = "detections:import"
    INTELLIGENCE_READ = "intelligence:read"
    INTELLIGENCE_PROPOSE = "intelligence:propose"
    INTELLIGENCE_MANAGE = "intelligence:manage"
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_MANAGE = "playbooks:manage"
    PLAYBOOKS_RUN = "playbooks:run"
    DEMO_RUN = "demo:run"
    REPORTS_READ = "reports:read"


_READ_PERMISSIONS = frozenset(
    {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.INCIDENTS_READ,
        Permission.HUNT_QUERY,
        Permission.DETECTIONS_READ,
        Permission.INTELLIGENCE_READ,
        Permission.PLAYBOOKS_READ,
        Permission.REPORTS_READ,
    }
)
_ANALYST_PERMISSIONS = _READ_PERMISSIONS | {
    Permission.ALERTS_MANAGE,
    Permission.INCIDENTS_EDIT,
    Permission.INCIDENTS_ASSIGN_SELF,
    Permission.INCIDENTS_CLOSE,
    Permission.HUNT_SAVE,
    Permission.DETECTIONS_DRAFT,
    Permission.DETECTIONS_TEST,
    Permission.INTELLIGENCE_PROPOSE,
    Permission.PLAYBOOKS_RUN,
}
_MANAGER_PERMISSIONS = _ANALYST_PERMISSIONS | {
    Permission.AUDIT_READ,
    Permission.SYSTEM_READ,
    Permission.INCIDENTS_ASSIGN_ANY,
    Permission.INCIDENTS_REOPEN,
    Permission.DETECTIONS_PUBLISH,
    Permission.DETECTIONS_IMPORT,
    Permission.INTELLIGENCE_MANAGE,
    Permission.PLAYBOOKS_MANAGE,
    Permission.DEMO_RUN,
}
ROLE_PERMISSIONS = MappingProxyType(
    {
        Role.ADMIN: frozenset(Permission),
        Role.SOC_MANAGER: _MANAGER_PERMISSIONS,
        Role.SOC_ANALYST: _ANALYST_PERMISSIONS,
        Role.READ_ONLY: _READ_PERMISSIONS,
    }
)


def permissions_for(role: Role | str) -> frozenset[Permission]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()


def has_permission(role: Role | str, permission: Permission | str) -> bool:
    try:
        return Permission(permission) in permissions_for(role)
    except ValueError:
        return False
