import type { SecurityEvent } from '../types';
import type { UebaEvidence, UebaReport } from './types';

const zero = '00000000-0000-0000-0000-000000000000';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function yesterdayUtc() {
  return new Date(Date.now() - 86400000).toISOString().slice(0, 10);
}
export function uebaPath(id: string, params: string, day: string) {
  const date = new Date(`${day}T00:00:00Z`);
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
    !Number.isFinite(date.getTime()) ||
    date.toISOString().slice(0, 10) !== day ||
    day < '1970-01-29' ||
    day > yesterdayUtc()
  )
    throw new Error('Wybierz zakończony dzień UTC, od 29 stycznia 1970 do wczoraj.');
  const source = new URLSearchParams(params);
  const mode = source.get('mode');
  if (mode !== 'live' && mode !== 'replay')
    throw new Error('Nie można ustalić trybu profilu. Otwórz profil ponownie.');
  const query = new URLSearchParams({ mode, day });
  if (mode === 'replay') {
    for (const key of ['dataset_id', 'run_id']) {
      const value = source.get(key) ?? '';
      if (!uuid.test(value) || value === zero)
        throw new Error('Replay wymaga dokładnego Dataset ID i Run ID profilu.');
      query.set(key, value.toLowerCase());
    }
  }
  return `/entities/${encodeURIComponent(id.toLowerCase())}/ueba?${query}`;
}
export function uebaEvidencePath(report: UebaReport, evidence: UebaEvidence) {
  const query = new URLSearchParams({
    mode: report.scope.mode,
    day: report.observation.from.slice(0, 10),
    document_sha256: evidence.document_sha256,
  });
  if (report.scope.mode === 'replay') {
    query.set('dataset_id', report.scope.dataset_id ?? '');
    query.set('run_id', report.scope.run_id ?? '');
  }
  return `/entities/${encodeURIComponent(report.entity.id)}/ueba/events/${encodeURIComponent(evidence.event_id)}?${query}`;
}
function exactUtc(value: string) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value);
  return match ? `${match[1]}.${(match[2] ?? '').padEnd(6, '0')}Z` : null;
}
export function matchesEvidence(event: SecurityEvent, evidence: UebaEvidence, report: UebaReport) {
  return (
    event.event_id === evidence.event_id &&
    exactUtc(event.timestamp) !== null &&
    exactUtc(event.timestamp) === exactUtc(evidence.timestamp) &&
    event.mode === report.scope.mode &&
    (report.scope.mode === 'live'
      ? event.run_id === zero
      : event.dataset_id === report.scope.dataset_id && event.run_id === report.scope.run_id)
  );
}
