import { ApiError } from '../api';
import { ErrorNotice } from '../components';

const messages: Record<string, string> = {
  ioc_not_found: 'Nie znaleziono IOC. Odśwież katalog.',
  ioc_exists: 'Ten IOC już istnieje z inną deklaracją. Otwórz go i edytuj bieżącą wersję.',
  ioc_catalog_limit: 'Osiągnięto limit lokalnego katalogu IOC. Operacja nie została zapisana.',
  ioc_revision_limit: 'Osiągnięto limit zachowanych rewizji tego IOC.',
  ioc_metadata_invalid: 'Sprawdź źródło, daty, reputację i pozostałe pola deklaracji IOC.',
  intelligence_evidence_integrity_mismatch:
    'Nie można potwierdzić zgodności zachowanego dopasowania IOC. Odśwież dowód; odczyt nie uruchamia ponownej analizy.',
};

export function IntelligenceFailure({ error }: { error: unknown }) {
  if (
    !(error instanceof ApiError) ||
    (!messages[error.code] && (error.status !== 422 || !error.detail))
  )
    return <ErrorNotice error={error} />;
  return (
    <div className="notice error" role="alert">
      {messages[error.code] ?? error.message}
      {error.status === 422 && error.detail && <p>{error.detail}</p>}
      {error.requestId && <small>Identyfikator żądania: {error.requestId}</small>}
    </div>
  );
}
