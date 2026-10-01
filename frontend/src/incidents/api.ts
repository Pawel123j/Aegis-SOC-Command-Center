import { api } from '../api';
import type { Page } from '../types';
import type {
  IncidentActor,
  IncidentCreate,
  IncidentDetail,
  IncidentEvidence,
  IncidentNote,
  IncidentPatch,
  IncidentTimelineEntry,
} from './types';

const path = (id: string) => `/incidents/${encodeURIComponent(id)}`;
const versionHeaders = (version: number) => ({ 'If-Match': `"${version}"` });
function pageQuery(cursor: string | null) {
  return new URLSearchParams({ limit: '50', ...(cursor ? { cursor } : {}) });
}

export const incidentsApi = {
  detail: (id: string) => api.get<IncidentDetail>(path(id)),
  create: (body: IncidentCreate, key: string) =>
    api.post<IncidentDetail>('/incidents', body, { 'Idempotency-Key': key }),
  patch: (id: string, body: IncidentPatch, version: number) =>
    api.patch<IncidentDetail>(path(id), body, version),
  attach: (id: string, alertId: string, version: number) =>
    api.post<IncidentDetail>(`${path(id)}/alerts`, { alert_id: alertId }, versionHeaders(version)),
  detach: (id: string, alertId: string, version: number) =>
    api.delete<IncidentDetail>(`${path(id)}/alerts/${encodeURIComponent(alertId)}`, version),
  note: (id: string, body: string, version: number) =>
    api.post<IncidentDetail>(`${path(id)}/notes`, { body }, versionHeaders(version)),
  assignees: () => api.get<{ items: IncidentActor[] }>('/incidents/assignees'),
  timeline: (id: string, cursor: string | null) =>
    api.get<Page<IncidentTimelineEntry>>(`${path(id)}/timeline?${pageQuery(cursor)}`),
  notes: (id: string, cursor: string | null) =>
    api.get<Page<IncidentNote>>(`${path(id)}/notes?${pageQuery(cursor)}`),
  evidence: (id: string, cursor: string | null) =>
    api.get<Page<IncidentEvidence>>(`${path(id)}/evidence?${pageQuery(cursor)}`),
};
