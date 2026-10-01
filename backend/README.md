# Backend — fundament i trwałe ingestion

FastAPI/Pydantic/SQLAlchemy tworzą modularny monolit z oddzielnym procesem Celery.
Runtime to **Python 3.12.14**, zgodny z obrazem Docker i konfiguracją CI. Zależności
runtime i developerskie mają osobne lockfile z hashami.

**Stan: PHASE 3 — normalizacja i wyszukiwanie, ukończona i zweryfikowana 2026-10-01.**
Fundament PHASE 1 obejmuje konfigurację i bezpieczne błędy, `/api/v1/auth`,
`/api/v1/users`, `/api/v1/audit`, chronione `/api/v1/system/health`, sondy `/health`
i `/ready`, wewnętrzne `/metrics` oraz OpenAPI pod `/api/v1/openapi.json`.
Migracja `0001_foundation` tworzy użytkowników, sesje i audyt w PostgreSQL.
Pierwsze konto tworzy `python -m app.bootstrap`; worker zachowuje zadanie
transportowe `aegis.ping`.

PHASE 2 dodaje `/api/v1/sources`, osobne credentiale ingestion, single/batch
pod `/api/v1/events`, idempotencję i trwały inbox/outbox w PostgreSQL.
Migracja `0002_ingestion` tworzy źródła, credentiale, potwierdzenia batchy,
surowe zdarzenia, zadania i liczniki pojemności. Oddzielny relay publikuje
identyfikatory do Redis, a worker `aegis.ingestion.stage` sprawdza integralność
i przygotowuje zdarzenie do normalizacji. Ograniczone retry, dzierżawy
i kwarantanna umożliwiają odzyskiwanie pracy; Admin może ponowić zdarzenie
z kwarantanny z kontrolą generacji przez `If-Match`.

`202` potwierdza zatwierdzony zapis, a `staged` oznacza gotowość raw do PHASE 3.
Status batcha i chronione `/api/v1/system/ingestion` udostępniają stan pracy
i pojemności. PHASE 3 dodaje sześć parserów, niezmienne snapshoty w PostgreSQL
(`0003_normalization`), trwałe zadania oraz processor projekcji ClickHouse.
Osobny migrator archiwum stosuje SQL z checksum i rozdziela właściciela od runtime.
API `/events/search` i `/events/{id}` udostępnia filtrowanie, podpisaną paginację
i odczyt z deduplikacją przed zliczeniem. Detekcje, UI i generator są kolejnymi
przyrostami. Wyniki: [raport PHASE 3](../docs/validation-phase3.md).

**Historyczny dowód: PHASE 1 ukończona i zweryfikowana 2026-09-28.** Przeszło 230 testów
jednostkowych oraz 33 testy integracyjne z rzeczywistymi PostgreSQL, Redis,
ClickHouse i Celery. Potwierdzono budowę obrazów Linux/Python 3.12.14, start
świeżego Compose, migracje, auth/RBAC i granty audytu. Instalacja dev lockfile
z `--require-hashes`, `pip check` oraz audyt runtime lock przeszły.
Hostowane CI pozostaje niezweryfikowane. Historyczne wyniki: [raport PHASE 1](../docs/validation-phase1.md).

Uruchomienie, sekrety, bootstrap i komendy testów:
[instrukcja operacyjna PHASE 1](../docs/phase1-operations.md).
Źródła, wysyłanie, status, limity i odzyskiwanie:
[instrukcja operacyjna PHASE 2](../docs/phase2-operations.md).
Normalizacja, wyszukiwanie i odzyskiwanie projekcji:
[instrukcja operacyjna PHASE 3](../docs/phase3-operations.md).
Zakres dalszych prac: [plan](../docs/implementation-plan.md).
Odpowiedzialność katalogów: [struktura](../docs/repository-structure.md).
