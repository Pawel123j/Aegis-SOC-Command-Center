import type { Me } from '../types';

export function canReadMitreCoverage(user: Me) {
  return ['detections:read', 'alerts:read', 'incidents:read'].every((permission) =>
    user.permissions.includes(permission),
  );
}
