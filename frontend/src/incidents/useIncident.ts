import { useCallback, useRef, useState } from 'react';
import { ApiError } from '../api';
import { useResource } from '../utilities';
import { incidentsApi } from './api';
import type { IncidentDetail } from './types';

export type IncidentMutation = (
  operation: (version: number) => Promise<IncidentDetail>,
) => Promise<IncidentDetail | null>;

export function useIncident(id: string) {
  const loader = useCallback(() => incidentsApi.detail(id), [id]);
  const resource = useResource(loader);
  const [confirmed, setConfirmed] = useState<IncidentDetail | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [conflict, setConflict] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const flight = useRef(false);
  const data =
    confirmed && (!resource.data || confirmed.version > resource.data.version)
      ? confirmed
      : resource.data;
  const mutate: IncidentMutation = async (operation) => {
    if (!data || flight.current || resource.pending || resource.error || conflict) return null;
    flight.current = true;
    setPending(true);
    setError(null);
    try {
      const result = await operation(data.version);
      setConfirmed(result);
      return result;
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError && failure.status === 412) setConflict(true);
      return null;
    } finally {
      flight.current = false;
      setPending(false);
    }
  };
  async function reload() {
    setError(null);
    setConflict(false);
    await resource.reload();
    setRefreshKey((value) => value + 1);
  }
  return {
    data,
    pending: pending || resource.pending,
    loading: resource.pending,
    error: error ?? resource.error,
    blocked: conflict || Boolean(resource.error),
    conflict,
    refreshKey,
    mutate,
    reload,
  };
}
