import { useState } from 'react';
import { Badge, Empty, JsonView, Loading, Panel } from '../components';
import type { Me } from '../types';
import { time } from '../utilities';
import { IntelligenceFailure } from './IntelligenceFailure';
import { IocEditor } from './IocEditor';
import { iocTypes, reputations, reputationTone } from './labels';
import type { Ioc, IocHistory } from './types';
import { useIntelligenceResource } from './useIntelligenceResource';
import type { IntelligenceScope } from './useIntelligenceScope';

export function IocDetails({
  id,
  user,
  scope,
  onBack,
  onChanged,
}: {
  id: string;
  user: Me;
  scope: IntelligenceScope;
  onBack: () => void;
  onChanged: () => void;
}) {
  const item = useIntelligenceResource<Ioc>(`/intelligence/iocs/${encodeURIComponent(id)}`, scope);
  const [editing, setEditing] = useState<Ioc | null>(null);
  const [historyVisible, setHistoryVisible] = useState(false);
  const history = useIntelligenceResource<IocHistory>(
    historyVisible ? `/intelligence/iocs/${encodeURIComponent(id)}/history` : null,
    scope,
  );
  return (
    <>
      <div className="intro">
        <button className="quiet" onClick={onBack}>
          ← Katalog IOC
        </button>
        <button disabled={item.pending || scope.expired || Boolean(editing)} onClick={item.reload}>
          Odśwież szczegóły IOC
        </button>
      </div>
      <IntelligenceFailure error={item.error} />
      {item.pending && <Loading />}
      {item.data && (
        <Panel title="Szczegóły wskaźnika">
          <h3 className="ioc-value mono">{item.data.value}</h3>
          <div className="detail-badges">
            <Badge>{iocTypes[item.data.type]}</Badge>
            <Badge tone={reputationTone[item.data.reputation]}>
              {reputations[item.data.reputation]}
            </Badge>
            <Badge>{item.data.active ? 'Aktywny' : 'Wyłączony'}</Badge>
          </div>
          <p>{item.data.description || 'Brak opisu od źródła.'}</p>
          <dl className="facts">
            <dt>Źródło deklaracji</dt>
            <dd>{item.data.source}</dd>
            <dt>Pewność deklarowana przez źródło</dt>
            <dd>{item.data.confidence === null ? 'Nieznana' : `${item.data.confidence}/100`}</dd>
            <dt>Pierwsza obserwacja według źródła</dt>
            <dd>{time(item.data.first_seen)}</dd>
            <dt>Ostatnia obserwacja według źródła</dt>
            <dd>{time(item.data.last_seen)}</dd>
            <dt>Bieżąca rewizja</dt>
            <dd>{item.data.revision}</dd>
            <dt>Ostatnia zmiana katalogu</dt>
            <dd>{time(item.data.updated_at)}</dd>
          </dl>
          <div className="intelligence-tags">
            {item.data.tags.map((tag) => (
              <Badge key={tag}>{tag}</Badge>
            ))}
          </div>
          <p className="notice">
            Dane są deklaracją źródła, a dopasowanie IOC nie potwierdza ataku. Deklarowana pewność
            nie jest skalibrowanym prawdopodobieństwem. Adresy URL pozostają tekstem.
          </p>
          <div className="button-row">
            {user.permissions.includes('intelligence:manage') && (
              <button
                disabled={scope.expired || Boolean(editing)}
                onClick={() => setEditing(item.data)}
              >
                Edytuj IOC
              </button>
            )}
            <button disabled={scope.expired} onClick={() => setHistoryVisible((value) => !value)}>
              {historyVisible ? 'Ukryj historię IOC' : 'Pokaż historię IOC'}
            </button>
          </div>
          <details>
            <summary>Pochodzenie bieżącej rewizji</summary>
            <dl className="facts">
              <dt>IOC ID</dt>
              <dd className="mono">{item.data.id}</dd>
              <dt>Revision ID</dt>
              <dd className="mono">{item.data.revision_id}</dd>
              <dt>SHA-256 deklaracji</dt>
              <dd className="mono">{item.data.document_sha256}</dd>
              <dt>Zasady normalizacji</dt>
              <dd>{item.data.normalization_version}</dd>
              <dt>Autor ostatniej zmiany</dt>
              <dd className="mono">{item.data.updated_by}</dd>
            </dl>
          </details>
        </Panel>
      )}
      {editing && (
        <IocEditor
          item={editing}
          scope={scope}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            item.reload();
            history.reload();
            onChanged();
          }}
        />
      )}
      {historyVisible && (
        <Panel
          title="Historia deklaracji IOC"
          aside={
            <button disabled={history.pending || scope.expired} onClick={history.reload}>
              Odśwież historię IOC
            </button>
          }
        >
          <p>
            Zmiany i wyłączenie zachowują poprzednie rewizje oraz wcześniejsze dopasowania. Historia
            obejmuje maksymalnie 50 rewizji tego wskaźnika.
          </p>
          <IntelligenceFailure error={history.error} />
          {history.pending && <Loading />}
          {history.data &&
            (history.data.items.length ? (
              <>
                <p>Rewizje: {history.data.total}.</p>
                <ol className="intelligence-history">
                  {history.data.items.map((revision) => (
                    <li key={revision.id}>
                      <strong>Rewizja {revision.revision}</strong>
                      <p>
                        {time(revision.created_at)} · autor{' '}
                        <span className="mono">{revision.created_by}</span>
                      </p>
                      <p className="mono ioc-value">SHA-256: {revision.document_sha256}</p>
                      <details>
                        <summary>Deklaracja rewizji {revision.revision}</summary>
                        <JsonView value={revision.document} />
                      </details>
                    </li>
                  ))}
                </ol>
              </>
            ) : (
              <Empty title="Brak zachowanych rewizji" />
            ))}
        </Panel>
      )}
    </>
  );
}
