import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError } from '../api';
import { Panel } from '../components';
import { IntelligenceFailure } from './IntelligenceFailure';
import { iocTypes, reputations } from './labels';
import type { Ioc, IocInput, IocMetadata } from './types';
import type { IntelligenceScope } from './useIntelligenceScope';

function localDate(value: string | null) {
  if (!value) return '';
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, -1);
}
function utcDate(value: string) {
  if (!value) return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error('Podaj poprawny czas obserwacji.');
  return date.toISOString();
}

export function IocEditor({
  item,
  scope,
  onSaved,
  onClose,
}: {
  item?: Ioc;
  scope: IntelligenceScope;
  onSaved: (ioc: Ioc) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState<IocInput>(() => ({
    type: item?.type ?? 'ip',
    value: item?.value ?? '',
    reputation: item?.reputation ?? 'unknown',
    confidence: item?.confidence ?? null,
    source: item?.source ?? '',
    first_seen: item?.first_seen ?? null,
    last_seen: item?.last_seen ?? null,
    tags: item?.tags ?? [],
    description: item?.description ?? '',
    active: item?.active ?? true,
  }));
  const [confidence, setConfidence] = useState(item?.confidence?.toString() ?? '');
  const [tags, setTags] = useState(item?.tags.join('\n') ?? '');
  const [firstSeen, setFirstSeen] = useState(localDate(item?.first_seen ?? null));
  const [lastSeen, setLastSeen] = useState(localDate(item?.last_seen ?? null));
  const [base, setBase] = useState(item);
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [failure, setFailure] = useState<{ epoch: number; value: unknown } | null>(null);
  const alive = useRef(true);
  const flight = useRef<number | null>(null);
  const pending = pendingEpoch === scope.epoch;
  useEffect(() => {
    const active = alive;
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  function current(epoch: number) {
    return alive.current && scope.isCurrent(epoch);
  }
  function field<K extends keyof IocInput>(name: K, value: IocInput[K]) {
    setDraft((valueBefore) => ({ ...valueBefore, [name]: value }));
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (flight.current === scope.capture() || blocked || scope.expired) return;
    const epoch = scope.capture();
    flight.current = epoch;
    setPendingEpoch(epoch);
    setFailure(null);
    try {
      if (!draft.value.trim() || !draft.source.trim())
        throw new Error('Podaj wartość wskaźnika i źródło deklaracji.');
      const certainty = confidence.trim() ? Number(confidence) : null;
      if (certainty !== null && (!Number.isInteger(certainty) || certainty < 0 || certainty > 100))
        throw new Error(
          'Deklarowana pewność musi być liczbą całkowitą od 0 do 100 albo pozostać pusta.',
        );
      const metadata: IocMetadata = {
        reputation: draft.reputation,
        confidence: certainty,
        source: draft.source.trim(),
        first_seen:
          firstSeen === localDate(draft.first_seen) ? draft.first_seen : utcDate(firstSeen),
        last_seen: lastSeen === localDate(draft.last_seen) ? draft.last_seen : utcDate(lastSeen),
        tags:
          tags === draft.tags.join('\n')
            ? draft.tags
            : tags
                .split(/\r?\n/)
                .map((tag) => tag.trim())
                .filter(Boolean),
        description: draft.description,
        active: draft.active,
      };
      if (
        metadata.first_seen &&
        metadata.last_seen &&
        new Date(metadata.first_seen).getTime() > new Date(metadata.last_seen).getTime()
      )
        throw new Error('Pierwsza obserwacja nie może być późniejsza od ostatniej.');
      const result = base
        ? await api.patch<Ioc>(
            `/intelligence/iocs/${encodeURIComponent(base.id)}`,
            metadata,
            base.version,
          )
        : await api.post<Ioc>('/intelligence/iocs', {
            ...metadata,
            type: draft.type,
            value: draft.value.trim(),
          });
      if (current(epoch)) onSaved(result);
    } catch (error) {
      if (current(epoch)) {
        setFailure({ epoch, value: error });
        if (base && error instanceof ApiError && [409, 412, 428].includes(error.status))
          setBlocked(true);
      }
    } finally {
      if (current(epoch)) setPendingEpoch(null);
      if (flight.current === epoch) flight.current = null;
    }
  }
  async function refreshVersion() {
    if (!base || flight.current === scope.capture() || scope.expired) return;
    const epoch = scope.capture();
    flight.current = epoch;
    setPendingEpoch(epoch);
    setFailure(null);
    try {
      const latest = await api.get<Ioc>(`/intelligence/iocs/${encodeURIComponent(base.id)}`);
      if (current(epoch)) {
        setBase(latest);
        setBlocked(false);
      }
    } catch (error) {
      if (current(epoch)) setFailure({ epoch, value: error });
    } finally {
      if (current(epoch)) setPendingEpoch(null);
      if (flight.current === epoch) flight.current = null;
    }
  }
  return (
    <Panel
      title={item ? 'Edytuj deklarację IOC' : 'Dodaj wskaźnik IOC'}
      aside={
        <button disabled={pending} onClick={onClose}>
          Zamknij formularz IOC
        </button>
      }
    >
      <p>
        Reputacja i pewność są deklaracją wskazanego źródła. Dopasowanie wskaźnika nie potwierdza
        ataku.
      </p>
      {base && (
        <p>
          Wersja do zapisu: {base.version}. Typ i wartość identyfikują wskaźnik i pozostają
          niezmienne.
        </p>
      )}
      <IntelligenceFailure
        error={failure?.epoch === scope.epoch && !scope.expired ? failure.value : null}
      />
      {blocked && (
        <p className="notice">
          Szkic pozostał w formularzu. Odśwież wersję IOC, porównaj dane i dopiero wtedy ponów
          zapis.
        </p>
      )}
      {item && (
        <button disabled={pending || scope.expired} onClick={() => void refreshVersion()}>
          Odśwież wersję IOC
        </button>
      )}
      <form className="intelligence-editor" onSubmit={(event) => void save(event)}>
        <fieldset disabled={pending || scope.expired}>
          <div className="form-row">
            <label>
              Typ IOC
              <select
                value={draft.type}
                disabled={Boolean(item)}
                onChange={(event) => field('type', event.target.value as IocInput['type'])}
              >
                {Object.entries(iocTypes).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Wartość wskaźnika
              <input
                required
                maxLength={2048}
                readOnly={Boolean(item)}
                value={draft.value}
                onChange={(event) => field('value', event.target.value)}
              />
            </label>
          </div>
          <div className="form-row">
            <label>
              Reputacja deklarowana
              <select
                value={draft.reputation}
                onChange={(event) =>
                  field('reputation', event.target.value as IocInput['reputation'])
                }
              >
                {Object.entries(reputations).map(([value, label]) => (
                  <option value={value} key={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Pewność deklarowana · opcjonalna
              <input
                type="number"
                min={0}
                max={100}
                step={1}
                value={confidence}
                onChange={(event) => setConfidence(event.target.value)}
                placeholder="Nieznana"
              />
            </label>
          </div>
          <label>
            Źródło deklaracji
            <input
              required
              maxLength={128}
              value={draft.source}
              onChange={(event) => field('source', event.target.value)}
              placeholder="Nazwa własnej analizy lub źródła"
            />
          </label>
          <div className="form-row">
            <label>
              Pierwsza obserwacja · czas lokalny
              <input
                type="datetime-local"
                step="0.001"
                value={firstSeen}
                onChange={(event) => setFirstSeen(event.target.value)}
              />
            </label>
            <label>
              Ostatnia obserwacja · czas lokalny
              <input
                type="datetime-local"
                step="0.001"
                value={lastSeen}
                onChange={(event) => setLastSeen(event.target.value)}
              />
            </label>
          </div>
          <label>
            Tagi IOC · jeden w wierszu
            <textarea
              value={tags}
              maxLength={1040}
              rows={3}
              onChange={(event) => setTags(event.target.value)}
            />
          </label>
          <p className="muted">Maksymalnie 16 tagów, do 64 znaków każdy.</p>
          <label>
            Opis IOC
            <textarea
              rows={4}
              maxLength={2048}
              value={draft.description}
              onChange={(event) => field('description', event.target.value)}
            />
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={draft.active}
              onChange={(event) => field('active', event.target.checked)}
            />
            Aktywny wskaźnik
          </label>
          <p className="muted">
            Wyłączenie zachowuje historię i wcześniejsze dowody. Zapis nie sprawdza ponownie
            starszych logów ani nie przelicza wcześniejszego ryzyka.
          </p>
          <button className="primary" disabled={blocked}>
            {pending ? 'Zapisywanie IOC…' : 'Zapisz IOC'}
          </button>
        </fieldset>
      </form>
    </Panel>
  );
}
