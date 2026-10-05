import type { EntityKind } from './types';

export const entityKinds: Record<EntityKind, string> = {
  host: 'Host',
  user: 'Konto',
  ip: 'Adres IP',
  process: 'Proces',
};
