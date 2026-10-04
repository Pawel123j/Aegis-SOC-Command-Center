# Backend — fundament i trwałe ingestion

FastAPI/Pydantic/SQLAlchemy tworzą modularny monolit z oddzielnym procesem Celery.
Runtime to **Python 3.12.14**, zgodny z obrazem Docker i konfiguracją CI. Zależności
runtime i developerskie mają osobne lockfile z hashami.

**Stan: PHASE 0–3, incydenty, korelacja, ryzyko, MITRE ATT&CK i Sigma — 2026-10-04.**
Migracja `0004_initial_alerts`, osobny `app.detector`, API alerts/detections
i atomowy checkpoint zapewniają trzy reguły pojedynczego zdarzenia.
[Zakres i ograniczenia](../docs/initial-soc.md).
Etap 1 rozbudowy dodaje `0005_incidents`: sprawy, powiązania alertów,
notatki, historię i idempotentne tworzenie. Nowy High/Critical alert tworzy
sprawę w tej samej transakcji detektora. [Kontrakt](../docs/incidents.md),
[wyniki regresji](../docs/validation-incidents.md).
Etap 2 dodaje pięć natywnych reguł korelacji, trwałe zadania i watermark,
zamknięty manifest replay oraz wielozdarzeniowe dowody alertu.
`app.correlator` działa osobno na tym samym obrazie; katalog, deployment,
test i stan są dostępne pod `/api/v1/correlations`.
[Decyzja](../docs/adr/0008-temporal-correlation.md),
[walidacja](../docs/validation-correlation.md).
Etap 3 dodaje osobny kalkulator `app.modules.risk`, niezmienne obliczenia
PostgreSQL oraz ograniczoną projekcję bieżącego wyniku. Alert i incydent
zachowują odrębne oceny; komplet powodów, braków i historii udostępnia API.
[Polityka](../docs/risk-engine.md), [decyzja](../docs/adr/0009-explainable-risk.md),
[walidacja](../docs/validation-risk.md).
Etap 4 dodaje `app.modules.mitre`, lokalny przypięty katalog oraz migrację
`0008_mitre`. Oddzielne append-only snapshoty nowych alertów zachowują wersję,
hash i nazwy; coverage liczy distinct alerty i aktywnie powiązane sprawy.
Nie zmienia oryginalnych reguł ani polityki ryzyka.
[Kontrakt](../docs/mitre.md), [wyniki](../docs/validation-mitre.md).
Etap 5 dodaje `app.modules.sigma`, migrację `0009_sigma` i API `/api/v1/sigma`.
YAML kompiluje się do ograniczonego AST; niezmienne rewizje są wyłączone przy
imporcie. Bieżąca publikacja działa przy kolejnych jobach istniejącego detektora.
Risk-policy-v3 przyjmuje deklarowaną severity osobno od kontrolowanych rodzin.
[Kontrakt](../docs/sigma.md), [walidacja Etapu 5](../docs/validation-sigma.md).
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
i odczyt z deduplikacją przed zliczeniem. Detekcje i panel działają w
początkowym przyroście SOC; Risk Engine rozwija Etap 3, Sigma Etap 5,
a generator pozostaje planowany.
Rozbudowa: [plan 15 etapów](../docs/soc-expansion-plan.md).
Wyniki: [raport PHASE 3](../docs/validation-phase3.md).

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
