import { ApiError } from '../api';
import { ErrorNotice } from '../components';

const messages: Record<string, string> = {
  sigma_rule_exists: 'Ta reguła już istnieje. Otwórz ją i zapisz nową wersję definicji.',
  sigma_rule_limit: 'Osiągnięto limit reguł Sigma. Import nie został zapisany.',
  sigma_revision_limit: 'Osiągnięto limit zachowanych wersji tej reguły.',
  sigma_definition_unchanged: 'Ta definicja jest już bieżącą wersją reguły.',
  sigma_id_mismatch: 'Nowa wersja musi zachować identyfikator Sigma bieżącej reguły.',
  sigma_rule_not_found: 'Nie znaleziono reguły Sigma. Odśwież katalog detekcji.',
  sigma_evidence_integrity_mismatch:
    'Zachowana definicja Sigma nie przeszła kontroli zgodności. Odśwież szczegóły.',
};

export function SigmaFailure({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || !error.code.startsWith('sigma_'))
    return <ErrorNotice error={error} />;
  return (
    <div className="notice error" role="alert">
      {messages[error.code] ?? 'Reguła Sigma nie została zaakceptowana.'}
      {error.status === 422 && error.detail && <p>{error.detail}</p>}
      <small>Kod: {error.code}</small>
      {error.requestId && <small>Identyfikator żądania: {error.requestId}</small>}
    </div>
  );
}
