import type { IocType, Reputation } from './types';
export const iocTypes: Record<IocType, string> = {
  ip: 'Adres IP',
  domain: 'Domena',
  url: 'Adres URL',
  hash: 'Hash pliku',
};
export const reputations: Record<Reputation, string> = {
  unknown: 'Nieznana',
  clean: 'Czysty według źródła',
  suspicious: 'Podejrzany',
  malicious: 'Złośliwy według źródła',
};
export const reputationTone: Record<Reputation, string | undefined> = {
  unknown: undefined,
  clean: 'success',
  suspicious: 'medium',
  malicious: 'high',
};
