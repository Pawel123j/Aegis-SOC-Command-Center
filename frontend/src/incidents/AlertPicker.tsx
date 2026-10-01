import { useCallback, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Loading } from '../components';
import type { Alert, Page } from '../types';
import { time } from '../utilities';
import { Pagination } from './Pagination';
import type { Incident } from './types';
import { usePage } from './usePage';

export function AlertPicker({
  selected,
  onSelect,
  scope,
  exclude = [],
  single = false,
}: {
  selected: Alert[];
  onSelect: (alerts: Alert[]) => void;
  scope?: Incident;
  exclude?: string[];
  single?: boolean;
}) {
  const [mode, setMode] = useState(scope?.mode ?? selected[0]?.mode ?? 'live');
  const first = selected[0];
  const replay = scope?.mode === 'replay' || (!scope && first?.mode === 'replay');
  const datasetId = replay ? (scope?.dataset_id ?? first?.dataset_id) : undefined;
  const runId = replay ? (scope?.run_id ?? first?.run_id) : undefined;
  return (
    <div>
      {!scope && (
        <label>
          Tryb alertów
          <select
            value={mode}
            onChange={(event) => {
              setMode(event.target.value);
              onSelect([]);
            }}
          >
            <option value="live">Live</option>
            <option value="replay">Replay</option>
          </select>
        </label>
      )}
      <p className="muted">
        {replay
          ? 'Alerty jednej sesji replay i jednego zestawu danych.'
          : 'Incydent live może łączyć alerty z różnych źródeł.'}
      </p>
      <AlertChoices
        key={`${mode}/${datasetId ?? ''}/${runId ?? ''}`}
        mode={mode}
        datasetId={datasetId}
        runId={runId}
        selected={selected}
        onSelect={onSelect}
        exclude={exclude}
        single={single}
      />
    </div>
  );
}

function AlertChoices({
  mode,
  datasetId,
  runId,
  selected,
  onSelect,
  exclude,
  single,
}: {
  mode: string;
  datasetId?: string | null;
  runId?: string;
  selected: Alert[];
  onSelect: (alerts: Alert[]) => void;
  exclude: string[];
  single: boolean;
}) {
  const loader = useCallback(
    (cursor: string | null) => {
      return api.get<Page<Alert>>(
        `/alerts?${new URLSearchParams({
          limit: '50',
          mode,
          ...(datasetId ? { dataset_id: datasetId } : {}),
          ...(runId ? { run_id: runId } : {}),
          ...(cursor ? { cursor } : {}),
        })}`,
      );
    },
    [mode, datasetId, runId],
  );
  const resource = usePage(loader);
  const candidates = resource.data?.items.filter((alert) => !exclude.includes(alert.id)) ?? [];
  return (
    <div>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {!!selected.length && (
        <p role="status">
          Wybrano: {selected.length}
          {single ? '' : ' / 100'}
        </p>
      )}
      {!resource.error && !resource.pending && !candidates.length && (
        <Empty title="Brak dostępnych alertów na tej stronie">
          Sprawdź kolejną stronę lub inny tryb. Możesz utworzyć pusty incydent live.
        </Empty>
      )}
      {!resource.error && candidates.length > 0 && (
        <div className="incident-choices" aria-busy={resource.pending}>
          {candidates.map((alert) => (
            <label className="incident-choice" key={alert.id}>
              <input
                type="checkbox"
                checked={selected.some((item) => item.id === alert.id)}
                disabled={resource.pending}
                onChange={(event) => {
                  if (event.target.checked) {
                    if (selected.length >= 100 && !single) return;
                    onSelect(single ? [alert] : [...selected, alert]);
                  } else onSelect(selected.filter((item) => item.id !== alert.id));
                }}
              />
              <span>
                <strong>{alert.title}</strong>
                <small>
                  {time(alert.event_timestamp)} · {alert.rule_id}
                </small>
                <Badge tone={alert.severity}>{alert.severity}</Badge>
              </span>
            </label>
          ))}
        </div>
      )}
      {resource.data && !resource.error && <Pagination {...resource.pagination} />}
    </div>
  );
}
