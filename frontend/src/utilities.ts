import { useCallback, useEffect, useRef, useState } from 'react';
export function time(value: string | null | undefined) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? '—'
    : new Intl.DateTimeFormat('pl-PL', { dateStyle: 'short', timeStyle: 'medium' }).format(parsed);
}
export function useResource<T>(loader: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(true);
  const sequence = useRef({ value: 0 });
  const reload = useCallback(async () => {
    const revision = ++sequence.current.value;
    setPending(true);
    setError(null);
    try {
      const result = await loader();
      if (sequence.current.value === revision) setData(result);
    } catch (failure) {
      if (sequence.current.value === revision) setError(failure);
    } finally {
      if (sequence.current.value === revision) setPending(false);
    }
  }, [loader]);
  useEffect(() => {
    const counter = sequence.current;
    let active = true;
    void Promise.resolve().then(() => {
      if (active) return reload();
    });
    return () => {
      active = false;
      counter.value++;
    };
  }, [reload]);
  return { data, error, pending, reload };
}

export const statusName: Record<string, string> = {
  new: 'Nowy',
  acknowledged: 'Potwierdzony',
  false_positive: 'Fałszywy alarm',
  resolved: 'Rozwiązany',
  pending: 'Oczekuje',
  processing: 'Przyjmowanie',
  processed: 'Sprawdzone przez reguły',
  staged: 'Raw zapisany',
  normalizing: 'Normalizacja',
  normalized: 'Znormalizowany',
  projecting: 'Archiwizacja',
  projected: 'W archiwum',
  quarantined: 'Kwarantanna',
  projection_failed: 'Błąd archiwizacji',
  success: 'Sukces',
  failure: 'Niepowodzenie',
  unknown: 'Nieznany',
};
