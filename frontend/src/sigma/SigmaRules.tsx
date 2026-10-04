import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Loading } from '../components';
import type { Me, SecurityEvent } from '../types';
import { SigmaCapabilities as Capabilities } from './SigmaCapabilities';
import { SigmaDetails } from './SigmaDetails';
import { SigmaEditor } from './SigmaEditor';
import { SigmaFailure } from './SigmaFailure';
import type { SigmaCapabilities, SigmaRule, SigmaRuleDetail } from './types';
import { useSigmaResource } from './useSigmaResource';
import { useSigmaScope } from './useSigmaScope';
import './sigma.css';

export function SigmaRules(props: { user: Me; onEvent: (event: SecurityEvent) => void }) {
  if (!props.user.permissions.includes('detections:read'))
    return (
      <Empty title="Reguły Sigma są niedostępne">
        Twoja rola nie pozwala na odczyt reguł detekcji.
      </Empty>
    );
  return (
    <SigmaRulesState
      key={`${props.user.id}/${props.user.role}/${[...props.user.permissions].sort().join(',')}`}
      {...props}
    />
  );
}

function SigmaRulesState({ user, onEvent }: { user: Me; onEvent: (event: SecurityEvent) => void }) {
  const scope = useSigmaScope();
  const rules = useSigmaResource<{ items: SigmaRule[] }>('/sigma/rules', scope);
  const capabilities = useSigmaResource<SigmaCapabilities>('/sigma/capabilities', scope);
  const [importing, setImporting] = useState<SigmaCapabilities | null>(null);
  const [selected, setSelected] = useState<{ id: string; capabilities: SigmaCapabilities } | null>(
    null,
  );
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
  const [blockedEpoch, setBlockedEpoch] = useState<number | null>(null);
  const [failure, setFailure] = useState<{ epoch: number; value: unknown } | null>(null);
  const [notice, setNotice] = useState<{ epoch: number; value: string } | null>(null);
  const pending = pendingEpoch === scope.epoch;
  const blocked = blockedEpoch === scope.epoch;
  async function refresh() {
    if (pending) return;
    if (scope.expired) {
      const epoch = scope.capture();
      setPendingEpoch(epoch);
      setFailure(null);
      try {
        const current = await api.get<Me>('/auth/me');
        if (!scope.isCurrent(epoch)) return;
        if (
          current.id !== user.id ||
          current.role !== user.role ||
          current.permissions.length !== user.permissions.length ||
          !user.permissions.every((permission) => current.permissions.includes(permission))
        )
          throw new Error(
            'Konto lub uprawnienia zmieniły się. Otwórz ponownie reguły z menu bieżącej sesji.',
          );
        scope.resume();
      } catch (value) {
        if (scope.isCurrent(epoch)) setFailure({ epoch, value });
      } finally {
        if (scope.isCurrent(epoch)) setPendingEpoch(null);
      }
      return;
    }
    setFailure(null);
    setNotice(null);
    setBlockedEpoch(null);
    rules.reload();
    capabilities.reload();
  }
  async function toggle(rule: SigmaRule) {
    if (pending || blocked || rules.pending || scope.expired) return;
    const epoch = scope.capture();
    setPendingEpoch(epoch);
    setFailure(null);
    setNotice(null);
    try {
      await api.patch<SigmaRuleDetail>(
        `/sigma/rules/${encodeURIComponent(rule.id)}`,
        { enabled: !rule.enabled },
        rule.version,
      );
      if (scope.isCurrent(epoch)) {
        rules.reload();
        setSelected(null);
      }
    } catch (value) {
      if (scope.isCurrent(epoch)) {
        setFailure({ epoch, value });
        setBlockedEpoch(epoch);
      }
    } finally {
      if (scope.isCurrent(epoch)) setPendingEpoch(null);
    }
  }
  function saved(rule: SigmaRuleDetail) {
    setImporting(null);
    const currentCapabilities = capabilities.data ?? importing ?? selected?.capabilities;
    setSelected(currentCapabilities ? { id: rule.id, capabilities: currentCapabilities } : null);
    setNotice({
      epoch: scope.epoch,
      value: `Zachowana definicja ${rule.revision}. Reguła: ${rule.enabled ? 'aktywna' : 'wyłączona'}.`,
    });
    rules.reload();
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Reguły Sigma</h2>
          <p>Importuj własne reguły, sprawdzaj warunki i zdecyduj o ich aktywacji.</p>
        </div>
        <div className="button-row">
          <button
            className="primary"
            disabled={scope.expired || pending || !capabilities.data || Boolean(importing)}
            onClick={() => setImporting(capabilities.data)}
          >
            {user.permissions.includes('detections:import')
              ? 'Import Sigma Rule'
              : 'Sprawdź YAML Sigma'}
          </button>
          <button
            disabled={pending || rules.pending || capabilities.pending}
            onClick={() => void refresh()}
          >
            Odśwież reguły Sigma
          </button>
        </div>
      </div>
      {scope.expired && (
        <ErrorNotice
          error={
            new Error('Sesja zmieniła się. Odśwież reguły Sigma po sprawdzeniu bieżącego konta.')
          }
        />
      )}
      <SigmaFailure
        error={
          rules.error ??
          capabilities.error ??
          (failure?.epoch === scope.epoch ? failure.value : null)
        }
      />
      {blocked && (
        <p className="notice">
          Odśwież reguły Sigma, aby pobrać aktualną wersję przed kolejną zmianą.
        </p>
      )}
      {notice?.epoch === scope.epoch && !scope.expired && (
        <p className="notice" role="status">
          {notice.value}
        </p>
      )}
      {(rules.pending || capabilities.pending) && <Loading />}
      {capabilities.data && <Capabilities capabilities={capabilities.data} />}
      {importing && (
        <SigmaEditor
          scope={scope}
          capabilities={importing}
          canSave={user.permissions.includes('detections:import')}
          onSaved={saved}
          onClose={() => setImporting(null)}
        />
      )}
      <div className="rule-grid">
        {rules.data?.items.map((rule) => (
          <article className="panel rule-card" key={rule.id}>
            <div className="panel-heading">
              <Badge tone={rule.severity}>{rule.severity}</Badge>
              <Badge tone={rule.enabled ? 'success' : undefined}>
                {rule.enabled ? 'Aktywna' : 'Wyłączona'}
              </Badge>
            </div>
            <h2>{rule.title}</h2>
            <p>{rule.description}</p>
            <small className="mono">
              {rule.id} · definicja {rule.revision} · stan {rule.version}
            </small>
            <p>Źródła: {rule.source_types.join(', ')}</p>
            <div className="button-row">
              <button
                disabled={!capabilities.data || scope.expired}
                onClick={() => {
                  if (capabilities.data)
                    setSelected({ id: rule.id, capabilities: capabilities.data });
                }}
                aria-label={`Przejrzyj Sigma: ${rule.title}`}
              >
                Warunki Sigma
              </button>
              {user.permissions.includes('detections:publish') && (
                <button
                  disabled={
                    pending || blocked || rules.pending || Boolean(rules.error) || scope.expired
                  }
                  onClick={() => void toggle(rule)}
                >
                  {rule.enabled ? 'Wyłącz Sigma' : 'Włącz Sigma'}
                </button>
              )}
            </div>
          </article>
        ))}
      </div>
      {rules.data?.items.length === 0 && (
        <Empty title="Brak reguł Sigma">
          Importowana reguła pojawi się tutaj jako wyłączona. Brak reguł nie potwierdza
          bezpieczeństwa źródeł.
        </Empty>
      )}
      {selected && (
        <SigmaDetails
          key={selected.id}
          id={selected.id}
          user={user}
          scope={scope}
          capabilities={selected.capabilities}
          onClose={() => setSelected(null)}
          onSaved={saved}
          onEvent={onEvent}
        />
      )}
    </>
  );
}
