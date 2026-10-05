import { Badge } from '../components';
import type { Json } from '../types';
import { reputations, reputationTone } from './labels';
import type { Reputation } from './types';

function object(value: Json | undefined): { [key: string]: Json } | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
}

export function AlertIntelligence({ reason }: { reason: Json }) {
  const proof = object(reason);
  if (!proof || !Array.isArray(proof.matches)) return null;
  return (
    <section aria-label="Deklaracje IOC zachowane przy alercie">
      <ol className="intelligence-history">
        {proof.matches.map((value, index) => {
          const match = object(value);
          const snapshot = object(match?.revision_snapshot);
          if (
            !match ||
            !snapshot ||
            typeof match.field !== 'string' ||
            typeof match.observed_value !== 'string' ||
            typeof snapshot.source !== 'string' ||
            typeof snapshot.reputation !== 'string' ||
            !Object.hasOwn(reputations, snapshot.reputation)
          )
            return null;
          const reputation = snapshot.reputation as Reputation;
          return (
            <li key={typeof match.id === 'string' ? match.id : index}>
              <strong>{match.field}</strong>
              <p className="ioc-value mono">Wartość z dowodu: {match.observed_value}</p>
              <Badge tone={reputationTone[reputation]}>{reputations[reputation]}</Badge>
              <dl className="facts">
                <dt>Źródło zachowanej deklaracji</dt>
                <dd>{snapshot.source}</dd>
                <dt>Pewność deklarowana w rewizji</dt>
                <dd>
                  {typeof snapshot.confidence === 'number'
                    ? `${snapshot.confidence}/100`
                    : 'Nieznana'}
                </dd>
                <dt>Zachowana rewizja IOC</dt>
                <dd>{typeof snapshot.revision === 'number' ? snapshot.revision : '—'}</dd>
                <dt>SHA-256 zachowanej rewizji</dt>
                <dd className="mono">
                  {typeof match.revision_snapshot_sha256 === 'string'
                    ? match.revision_snapshot_sha256
                    : '—'}
                </dd>
              </dl>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
