import type { Json } from '../types';

const stages: Record<string, string> = {
  failed_logins: 'Nieudane logowania',
  successful_login: 'Udane logowanie',
  powershell_started: 'Uruchomienie PowerShell',
  outbound_connection: 'Połączenie wychodzące',
  administrator_group_change: 'Zmiana lokalnej grupy administratorów',
};
const groups: Record<string, string> = {
  same_user: 'użytkownik',
  same_host: 'host',
  same_ip: 'IP źródłowy',
  same_process: 'trwały identyfikator procesu',
};

export function EventReason({ reason }: { reason: Json }) {
  if (typeof reason !== 'object' || reason === null || Array.isArray(reason)) return null;
  if (typeof reason.summary === 'string') return <p>{reason.summary}</p>;
  if (reason.kind !== 'sequence' && reason.kind !== 'threshold') return null;
  const groupBy = reason.group_by;
  const identities =
    typeof groupBy === 'object' && groupBy !== null && !Array.isArray(groupBy)
      ? Object.keys(groupBy)
          .map((field) => groups[field] ?? field)
          .join(', ')
      : '';
  return (
    <div>
      <p>
        Dopasowano {reason.kind === 'sequence' ? 'kolejne etapy' : 'próg liczby zdarzeń'}
        {typeof reason.window_seconds === 'number' ? ` w oknie ${reason.window_seconds} s` : ''}.
        {identities ? ` Wspólne encje: ${identities}.` : ''}
      </p>
      {Array.isArray(reason.stages) && (
        <ol>
          {reason.stages.map((stage, index) => {
            if (typeof stage !== 'object' || stage === null || Array.isArray(stage)) return null;
            return (
              <li key={index}>
                {typeof stage.name === 'string'
                  ? (stages[stage.name] ?? stage.name)
                  : `Etap ${index + 1}`}
                {Array.isArray(stage.event_ids)
                  ? ` · zdarzenia dowodowe: ${stage.event_ids.length}`
                  : ''}
                {typeof stage.required_count === 'number'
                  ? ` · wymagane: ${stage.required_count}`
                  : ''}
              </li>
            );
          })}
        </ol>
      )}
      {reason.assessment === 'potential_activity_requires_analyst_review' && (
        <p className="muted">
          Zaobserwowana aktywność wymaga analizy. Sprawdź kontekst każdego zachowanego zdarzenia.
        </p>
      )}
    </div>
  );
}
