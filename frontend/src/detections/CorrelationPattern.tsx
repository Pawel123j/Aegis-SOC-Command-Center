import type { CorrelationCondition, CorrelationPattern as Pattern } from './types';

const fields: Record<string, string> = {
  'source.type': 'Typ źródła',
  'event.category': 'Kategoria zdarzenia',
  'event.type': 'Typ zdarzenia',
  'event.action': 'Akcja',
  'event.outcome': 'Wynik',
  'event.code': 'Kod zdarzenia',
  'process.name': 'Nazwa procesu',
  'process.command_line': 'Polecenie procesu',
  'user.name': 'Użytkownik',
  'user.target.name': 'Konto docelowe',
};
const operators = { equals: 'równa się', contains: 'zawiera', endswith: 'kończy się na' };
const identities = {
  same_user: 'Ten sam użytkownik',
  same_host: 'Ten sam host',
  same_ip: 'Ten sam IP źródłowy',
  same_process: 'Ten sam trwały identyfikator procesu',
};
const stages: Record<string, string> = {
  failed_logins: 'Nieudane logowania',
  successful_login: 'Udane logowanie',
  powershell_started: 'Uruchomienie PowerShell',
  outbound_connection: 'Połączenie wychodzące',
  administrator_group_change: 'Zmiana lokalnej grupy administratorów',
};

export function CorrelationPattern({ pattern }: { pattern: Pattern }) {
  return (
    <div className="correlation-pattern">
      <dl className="facts">
        <dt>Rodzaj dopasowania</dt>
        <dd>
          {pattern.kind === 'sequence'
            ? 'Sekwencja w kolejności czasu zdarzeń'
            : 'Próg liczby zdarzeń'}
        </dd>
        <dt>Okno czasowe</dt>
        <dd>
          {pattern.window_seconds} s ({pattern.window_seconds / 60} min)
        </dd>
        <dt>Wspólne encje</dt>
        <dd>{pattern.group_by.map((identity) => identities[identity]).join(' + ')}</dd>
      </dl>
      <ol className="correlation-stages">
        {pattern.stages.map((stage, index) => (
          <li key={`${index}-${stage.name}`}>
            <strong>{stages[stage.name] ?? stage.name}</strong>
            <p>Minimalna liczba zdarzeń: {stage.count}</p>
            <Condition condition={stage.condition} />
          </li>
        ))}
      </ol>
    </div>
  );
}

function Condition({ condition }: { condition: CorrelationCondition }) {
  const group = condition.all ?? condition.any;
  if (group)
    return (
      <div className="correlation-condition">
        <span>{condition.all ? 'Wszystkie warunki (AND)' : 'Dowolny warunek (OR)'}</span>
        <ul>
          {group.map((item, index) => (
            <li key={index}>
              <Condition condition={item} />
            </li>
          ))}
        </ul>
      </div>
    );
  return (
    <span>
      {fields[condition.field ?? ''] ?? condition.field}{' '}
      {condition.operator ? operators[condition.operator] : ''} <code>{condition.value}</code>
    </span>
  );
}
