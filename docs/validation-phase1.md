# Raport walidacji PHASE 1

Data kontroli: 2026-09-28. Zakres: fundament backendu, auth/RBAC, audyt,
konfiguracja, migracje, obserwowalność i infrastruktura lokalna.
Poprzedni przyrost opisuje [historyczny raport PHASE 0](validation-phase0.md).

## Stan bramki

**PHASE 1: bramka funkcjonalna i jakościowa zaliczona.** Obrazy zbudowano,
stos wystartował, migracje i 33 integracje przeszły na rzeczywistych usługach.
Przyrost obejmuje 230 pozytywnych unit i 33 pozytywne integracje; PHASE 2
pozostaje zaplanowana. Nie jest to final audit platformy z PHASE 20.

## Wykonane kontrole

| Kontrola | Wynik / zakres |
| --- | --- |
| Python i zależności | Python 3.12.14 x64; instalacja dev lockfile z `--require-hashes` oraz `pip check` zakończone powodzeniem; wspólne piny runtime/dev zgodne |
| Audyt zależności runtime | `pip_audit -r backend/requirements.lock --strict --require-hashes`: exit 0, brak znanych podatności według źródła audytu w dniu kontroli; nie obejmuje obrazów OS ani pakietów dev |
| Testy jednostkowe | `pytest -m "not integration" -p no:cacheprovider --cov=app`: **230 passed, 32 deselected in 16.40s**; po tym pomiarze dodano kolejny test integracyjny |
| Coverage jednostkowe | **65%** łącznie z gałęziami; nie jest to coverage całego stosu ani dowód poprawności transakcji |
| Ruff | `ruff check .` oraz `ruff format --check .`: PASS, 45 plików zgodnych z formatowaniem |
| Typy | `mypy --cache-dir ../.local/mypy`: PASS, 29 plików aplikacji |
| Migracja offline | `alembic upgrade head --sql`: PASS; generuje SQL PostgreSQL, nie zastępuje wykonania na bazie |
| Konfiguracja Compose | `docker compose config --quiet`: PASS, bez wypisywania sekretów |
| Docker Engine | `docker info`: serwer 29.7.2, uruchomiony po naprawie lokalnej ścieżki instalacji |
| Obrazy | `docker compose build api` oraz `docker compose --profile test build tests`: PASS na Linux/Python 3.12.14, hashe zależności zweryfikowane |
| Pierwszy start usług | `docker compose up -d --wait --wait-timeout 180`: PASS na nowych wolumenach; PostgreSQL, Redis, ClickHouse i API gotowe; migrator exit 0 |
| Integracje | `pytest -m integration -p no:cacheprovider --cov=app`: **33 passed, 230 deselected in 32.30s** w kontenerze, na rzeczywistych usługach |
| Coverage integracyjne | **82%** procesu testowego; mierzone oddzielnie od unit, bez sumowania procentów; wykonanie `aegis.ping` w osobnym workerze potwierdza test transportu, nie pomiar coverage tego procesu |
| Proxy i żywe API | `/health` 200, `/ready` 200, `/metrics` 404, `/api/v1/openapi.json` 200, `/api/v1/users` bez auth 401; nagłówki bezpieczeństwa API obecne |
| Struktura i tekst | Walidator repozytorium: PASS, 97 plików tekstowych, 43 wymagane katalogi, 21 faz, 37 wymagań i 6 ADR; linki, format i składnia |
| Stan po testach | 0 pozostałych baz `aegis_test_%`; 0 użytkowników w głównej bazie, więc interaktywny bootstrap pierwszego administratora pozostaje dostępny |
| Poufne pliki lokalne | `.env`, `.venv`, `.local` i plik coverage są ignorowane przez Git |

Testy unit obejmują konfigurację fail-closed, macierz permissions, JWT,
Argon2id, limiter, redakcję logów, sondy i granice HTTP. Wykorzystują kontrolowane
zależności, dlatego nie zamykają testów auth z PostgreSQL ani transportu Celery.
Brak cache pytest na Windows omija błąd uprawnień do pliku cache; ostrzeżenia
nadal są traktowane jako błędy.

Zestaw integracyjny używa odrębnych baz `aegis_test_<UUID>`, prawdziwego Redis,
ClickHouse i workera. Sprawdza migracje w obie strony, zgodność modeli, granty
runtime, atomowość audytu, bootstrap, sesje, role, paginację, awarie i równoległy
refresh z cofnięciem uprawnień. Wymagane integracje nie są automatycznie pomijane,
gdy konfiguracja lub usługa są niedostępne.

## Poprawki wynikające z kontroli

- Dodano odczyt `alembic_version` dla roli aplikacji, wymagany przez `/ready`.
- Uzupełniono dev lockfile o `httpx2`, wymagane przez aktualny TestClient Starlette.
- Odrzucono nieprawidłowe typy identyfikatorów JWT i pól logowania przed ich użyciem.
- Middleware dopuszcza puste żądania refresh/logout; niepuste body nadal wymaga
  JSON i mieści się w 64 KiB, niezależnie od deklarowanego Content-Length.
- Zmiany użytkownika blokują rekord przez `FOR NO KEY UPDATE`, aby nie tworzyć
  cyklu blokad z sesją i kluczem obcym audytu przy refresh/logout. SQLAlchemy
  wygenerowało oczekiwany SQL; test rzeczywistej współbieżności przeszedł.
  Kontrolowana zamiana na poprzednie `FOR UPDATE` wyłącznie w jednorazowym
  procesie testowym odtworzyła odmowę PATCH 503 i negatywny wynik tego testu.
  Ponowne uruchomienie z poprawką dało **1 passed in 1.39s**.
  Kod ani obraz aplikacji nie zostały cofnięte.
- Pierwszy start Compose wykrył rozbicie opcji `tmpfs` na osobne elementy YAML.
  Ujęto ciągi opcji w cudzysłowy; po poprawce pełny start przeszedł.

Semantykę blokad potwierdzają [PostgreSQL](https://www.postgresql.org/docs/17/explicit-locking.html)
i [SQLAlchemy](https://docs.sqlalchemy.org/en/20/core/selectable.html#sqlalchemy.sql.expression.GenerativeSelect.with_for_update).

## Środowisko lokalne i ograniczenia

Docker Desktop nie startował przez stare gniazda i wirtualną ścieżkę instalacji
MSIX niewidoczną dla WSL. Odtworzono katalogi gniazd, a następnie skorygowano
pojedynczą wartość `HKCU/.../Uninstall/Docker Desktop/InstallLocation` na istniejącą
fizyczną lokalizację. Poprzednią wartość zachowano w pliku
`%TEMP%/aegis-docker-installlocation-20260928.json`. Nie resetowano danych silnika
ani nie przeinstalowano systemu. Jest to naprawa tego hosta, nie krok instalacji
wymagany od każdego użytkownika projektu.

[Workflow backendu](../.github/workflows/backend.yml) zawiera osobne zadania jakości
i integracji. Repozytorium nie ma remote, więc GitHub Actions nie został wykonany.
Nie deklarujemy zielonego hostowanego CI ani pełnego audytu bezpieczeństwa platformy.
UI, ingestion, detekcje, korelacje i pozostałe moduły należą do kolejnych faz.

Instrukcja odtworzenia i polecenia: [obsługa PHASE 1](phase1-operations.md).

## Rejestr przyrostu

Conventional Commit: `feat: add verified backend foundation and local infrastructure`.
Identyfikator rewizji można odczytać przez `git log -1 --oneline`.
Commit korzysta z tożsamości `Codex <codex@openai.com>` tylko dla tej komendy,
bez zmiany globalnych ustawień Git. Nie utworzono remote ani nie wykonano push.
