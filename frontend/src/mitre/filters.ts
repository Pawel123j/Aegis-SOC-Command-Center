export interface CoverageFilter {
  mode: 'live' | 'replay';
  from: string;
  to: string;
  dataset_id: string;
  run_id: string;
  include_false_positives: boolean;
}

export function localInput(date: Date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export function initialCoverageFilter(): CoverageFilter {
  const to = new Date(Math.floor(Date.now() / 60000) * 60000);
  return {
    mode: 'live',
    from: localInput(new Date(to.getTime() - 30 * 86400000)),
    to: localInput(to),
    dataset_id: '',
    run_id: '',
    include_false_positives: false,
  };
}

export function coveragePath(filter: CoverageFilter) {
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
    include_false_positives: String(filter.include_false_positives),
  });
  if (filter.mode === 'replay') {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (
      !uuid.test(filter.dataset_id) ||
      !uuid.test(filter.run_id) ||
      filter.run_id === '00000000-0000-0000-0000-000000000000'
    ) {
      throw new Error(
        'Replay wymaga poprawnego Dataset ID oraz niezerowego Run ID tej samej sesji.',
      );
    }
    params.set('dataset_id', filter.dataset_id);
    params.set('run_id', filter.run_id);
  }
  return `/mitre/coverage?${params}`;
}
