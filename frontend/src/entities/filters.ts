import type { SecurityEvent } from '../types';
import { localInput } from '../mitre/filters';
import type { EntityKind } from './types';

export interface EntityFilter {
  mode: 'live' | 'replay';
  from: string;
  to: string;
  dataset_id: string;
  run_id: string;
  kind: EntityKind | '';
  q: string;
  limit: number;
}
export function initialEntityFilter(): EntityFilter {
  const end = new Date(Math.floor(Date.now() / 60000) * 60000);
  return {
    mode: 'live',
    from: localInput(new Date(end.getTime() - 30 * 86400000)),
    to: localInput(end),
    dataset_id: '',
    run_id: '',
    kind: '',
    q: '',
    limit: 25,
  };
}
export function entityParams(filter: EntityFilter, search = true) {
  if (!Number.isInteger(filter.limit) || filter.limit < 1 || filter.limit > 100)
    throw new Error('Wybierz limit od 1 do 100 profili na stronę.');
  const from = new Date(filter.from);
  const to = new Date(filter.to);
  if (
    Number.isNaN(from.getTime()) ||
    Number.isNaN(to.getTime()) ||
    from >= to ||
    to.getTime() > Date.now() ||
    to.getTime() - from.getTime() > 366 * 86400000
  ) {
    throw new Error('Wybierz poprawny zakres czasu, maksymalnie 366 dni, bez daty w przyszłości.');
  }
  const params = new URLSearchParams({
    mode: filter.mode,
    from: from.toISOString(),
    to: to.toISOString(),
    limit: String(filter.limit),
  });
  if (filter.mode === 'replay') {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (
      !uuid.test(filter.dataset_id) ||
      !uuid.test(filter.run_id) ||
      filter.dataset_id === '00000000-0000-0000-0000-000000000000' ||
      filter.run_id === '00000000-0000-0000-0000-000000000000'
    ) {
      throw new Error('Replay wymaga niezerowego Dataset ID oraz niezerowego Run ID.');
    }
    params.set('dataset_id', filter.dataset_id);
    params.set('run_id', filter.run_id);
  }
  if (search && filter.kind) params.set('kind', filter.kind);
  if (search && filter.q.trim()) {
    if (filter.q.length > 128 || [...filter.q].some((character) => character.charCodeAt(0) < 32)) {
      throw new Error('Nazwa może mieć do 128 znaków, bez znaków sterujących.');
    }
    params.set('q', filter.q.trim());
  }
  return params.toString();
}
export function eventEntityParams(event: SecurityEvent) {
  const timestamp = new Date(event.timestamp).getTime();
  const end = Math.min(Date.now(), timestamp + 1);
  if (!Number.isFinite(timestamp) || timestamp >= end) return null;
  const params = new URLSearchParams({
    mode: event.mode,
    from: new Date(timestamp).toISOString(),
    to: new Date(end).toISOString(),
    limit: '100',
  });
  if (event.mode === 'replay') {
    params.set('dataset_id', event.dataset_id);
    params.set('run_id', event.run_id);
  }
  return params.toString();
}
export function profileFilterForEvent(event: SecurityEvent): EntityFilter {
  const filter = initialEntityFilter();
  const timestamp = new Date(event.timestamp).getTime();
  const end = Math.min(Date.now(), timestamp + 86400000);
  return {
    ...filter,
    mode: event.mode === 'replay' ? 'replay' : 'live',
    dataset_id: event.mode === 'replay' ? event.dataset_id : '',
    run_id: event.mode === 'replay' ? event.run_id : '',
    from: eventLocalInput(new Date(timestamp - 29 * 86400000)),
    to: eventLocalInput(new Date(end)),
  };
}
function eventLocalInput(date: Date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, -1);
}
