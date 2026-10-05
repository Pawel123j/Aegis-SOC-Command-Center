import type { Me } from '../types';

export function canReadEntities(user: Me) {
  return ['events:read', 'alerts:read', 'incidents:read'].every((permission) =>
    user.permissions.includes(permission),
  );
}
