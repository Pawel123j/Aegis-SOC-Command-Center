# Raport walidacji PHASE 2

Data kontroli: 2026-09-30. Zakres: trwałe przyjmowanie zdarzeń, źródła,
credentiale, single/batch, idempotencja, inbox/outbox, relay, worker, status,
retry i backpressure. Historyczne wyniki fundamentu zachowuje
[raport PHASE 1](validation-phase1.md).

Późniejszy przyrost uruchamiania z folderu i obsługiwanej budowy offline opisuje
[walidacja lokalnego startu](validation-startup.md). Poniższe liczby regresji
oraz opis pierwotnego wariantu build zachowują przebieg zamknięcia PHASE 2.

## Stan bramki

**PHASE 2: bramka funkcjonalna i jakościowa zaliczona.** Końcowy wspólny przebieg
na Linux/Python 3.12.14 dał **454 passed in 106.81s**: 341 testów jednostkowych
oraz 113 integracyjnych. Rzeczywiste PostgreSQL, Redis, ClickHouse, HTTP, relay
oraz prefork Celery potwierdzają trwałe admission i odzyskiwanie pracy.

`202` potwierdza zapis transakcji. `staged` oznacza gotowość raw do normalizacji.
Nie ma jeszcze normalizacji, wyszukiwania, detekcji, alertów, UI ani generatora.
Następna faza to PHASE 3; pełne Definition of Done platformy pozostaje otwarte.

## Wykonane kontrole

| Kontrola | Wynik / zakres |
| --- | --- |
| Pełna regresja | **454 passed in 106.81s**, bez pominiętych testów na Linux; wspólny przebieg unit i integracji |
| Coverage | **91%**, z gałęziami, procesu testowego; 1921 statements i 384 branches; nie obejmuje osobnych procesów relay/worker/API |
| Ruff | `ruff check .`: PASS; `ruff format --check .`: PASS, 61 plików |
| Typy | `mypy --cache-dir ../.local/mypy`: PASS, 37 plików aplikacji |
| Zależności | `pip check`: PASS; runtime/dev lockfile z hashami zainstalowane w obrazach Linux z `--require-hashes` |
| Audyt runtime | `pip_audit -r backend/requirements.lock --strict --require-hashes`: PASS, brak znanych podatności według źródła audytu w dniu kontroli; użyto zaufanych CA Windows |
| Alembic offline | `upgrade head --sql`: PASS przez `0001_foundation` i `0002_ingestion`; nie zastępuje wykonania na bazie |
| Migracje i granty | Integracje: PASS na rzeczywistym PostgreSQL, modele i uprawnienia runtime zgodne |
| Compose | `docker compose config --quiet`: PASS; Docker Engine 29.7.2; świeży, odrębny projekt `aegis-validation-20260930` |
| Obrazy | API i tests: PASS; lokalny build z wheelhouse oraz identycznymi lockfile/hashami, opisany poniżej |
| Start usług | `up -d --no-build --wait --wait-timeout 180`: PASS; migrator exit 0; API, bazy, relay i worker uruchomione |
| HTTP → relay → prefork | PASS; osobne procesy Uvicorn, relay i production factory Celery; zdarzenie osiąga `staged` |
| Stop/restart workera | PASS; podczas zatrzymania nowe zdarzenie zostaje przyjęte i rzeczywiście trafia do unikalnej kolejki Redis; po starcie workera `staged`, generation 1, attempts 1 |
| Współbieżne admission | Po poprawce inicjalizacji schematów **30 passed in 25.08s** na odrębnych bazach; limit 1 dopuszcza jedno 202 i jedno kontrolowane 503 |
| Proxy | `nginx -t`: PASS; rzeczywista zmiana adresu API `172.18.0.7 → 172.18.0.200` odzyskana bez restartu proxy |
| Sondy i ochrona | `/health` 200, `/ready` 200, `/metrics` 404, OpenAPI 200, nieuwierzytelnione `/api/v1/users` 401; sprawdzone przez proxy |
| Dokumentacja | Walidator repozytorium i `git diff --check`: PASS; 117 plików tekstowych, 43 katalogi, 21 faz, 37 wymagań, 6 ADR |
| Sprzątanie baz testowych | 0 pozostałych baz `aegis_test_%`; 0 użytkowników w głównej bazie odrębnego stosu walidacyjnego |

Coverage 91% jest jednym pomiarem wspólnego przebiegu, a nie sumą historycznych
wartości unit/integration. Osobne procesy mają dowód zachowania w teście,
bez deklaracji ich pokrycia instrumentation.

## Poprawki wynikające z kontroli

- Test współbieżnego admission wykrył sporadyczne 500 przed wejściem do serwisu.
  Diagnostyka ograniczona do typu wyjątku i lokalizacji wskazała
  `UnsupportedFieldAttributeWarning` podczas leniwej budowy schematów FastAPI.
  Przed poprawką seria 30 prób dała 3 błędy i 27 pozytywnych wyników.
  Fabryka aplikacji serializuje teraz budowę i wywołuje publiczne `openapi()`
  przed obsługą żądań. Oba deterministyczne testy w `test_app.py` wykryły stary
  kod i przeszły z poprawką; po niej przeszło również 30 prób admission.
  Mechanikę globalnych filtrów ostrzeżeń opisuje
  [dyskusja FastAPI](https://github.com/fastapi/fastapi/discussions/15914).
- Wspólny przebieg w Compose ujawnił dziedziczenie `AEGIS_LOCAL_HTTP=true`
  przez dwie fixture z publicznym HTTPS. Fixture jawnie ustawiają teraz
  `local_http=false`; pełny zestaw przechodzi także w środowisku integracyjnym.
- Wymiana API zmieniła jego IP, a proxy nadal próbowało starego adresu (502).
  Upstream Nginx korzysta teraz z `resolve`, współdzielonej strefy i DNS Docker
  `127.0.0.11` z odświeżaniem co 5 s. Kontrolowana zmiana IP potwierdziła
  samoczynne odzyskanie `/ready` bez restartu proxy. Semantyka:
  [Nginx](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#resolve),
  [Docker DNS](https://docs.docker.com/engine/network/#dns-services).
- Zaktualizowano stare statusy PHASE 0/1 w dokumentacji oraz dodano test pełnego
  przepływu przez osobne procesy i procedury obserwowania aktualizacji API.

## Odtworzenie testów

Z katalogu głównego, po standardowym przygotowaniu `.env` i usług:

```powershell
docker compose config --quiet
docker compose build api
docker compose --profile test build tests
docker compose up -d --wait --wait-timeout 180
docker compose --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests pytest -p no:cacheprovider --cov=app --cov-report=term --tb=short
```

`COVERAGE_FILE=/tmp/.coverage` jest wymagane przy pomiarze w kontenerze z
read-only `/app`. Cache pytest wyłączono; ostrzeżenia nadal są błędami.
Domyślny profil tests uruchamia tylko integracje. Powyższe jawne polecenie
uruchamia cały zestaw. Test deployed wymaga Linux i prefork; na Windows ma
jawny platform skip, dlatego jego dowodem jest wykonanie w kontenerze Linux.
Każda integracja tworzy własną bazę `aegis_test_<UUID>`; kolejki testowe mają
unikalne nazwy. Testy nie czyszczą głównej bazy ani wspólnych kluczy Redis.

Kontrole jakości z katalogu `backend`:

```powershell
..\.venv\Scripts\python.exe -m ruff check .
..\.venv\Scripts\python.exe -m ruff format --check .
..\.venv\Scripts\python.exe -m mypy --cache-dir ..\.local\mypy
```

## Odstępstwo lokalnego build i ograniczenia

Ta sekcja rejestruje pierwotną kontrolę PHASE 2. Obsługiwany Dockerfile ma teraz
tryb offline z `compose.offline.yaml` i sprawdzanym wheelhouse; jego dowody
oraz aktualne komendy zawiera [walidacja startu](validation-startup.md).

Na tym hoście bezpośredni download PyPI wewnątrz standardowego Docker build
zatrzymał błąd zaufania certyfikatu. Nie wyłączano TLS i nie zmieniano pinów.
Bundled Python pobrał 91 zgodnych wheel Linux/CPython 3.12, z wymaganymi hashami,
do ignorowanego `backend/.local/wheelhouse`. Lokalny wariant Dockerfile różnił
się dodaniem wheelhouse oraz `--no-index --find-links=/wheels` do instalacji.
Wykorzystano te same runtime/dev lockfile i weryfikację `--require-hashes`.
Plik pomocniczy i override Compose pozostają w ignorowanych katalogach `.local`;
produkcyjny Dockerfile nie został zmieniony. Standardowy build pobierający PyPI
na tym hoście pozostaje zależny od poprawnego zaufania CA w kontenerze.

Wykonany lokalny build z przygotowanym wariantem:

```powershell
docker compose -p aegis-validation-20260930 -f compose.yaml -f .local/compose-validation.yaml build api tests
```

Wheelhouse pobrano przez `python -I -u -m pip download --require-hashes`
z `--only-binary=:all: --implementation cp --python-version 3.12 --abi cp312`,
`-r backend/requirements-dev.lock -d backend/.local/wheelhouse` i platformami
`manylinux_2_36_x86_64`, `manylinux_2_35_x86_64`, `manylinux_2_34_x86_64`,
`manylinux_2_28_x86_64`, `manylinux_2_27_x86_64`, `manylinux_2_17_x86_64`
oraz `manylinux2014_x86_64` (osobny argument `--platform` dla każdej).

Audyt runtime po błędzie CA zakończył się poprawnie przez istniejący
`pip._vendor.truststore` i zaufane certyfikaty Windows, z aktywnym TLS.
Nie obejmuje to audytu obrazów OS ani wszystkich narzędzi developerskich.

Test osobnych procesów wykonuje rzeczywisty graceful stop/restart workera.
Testy przerwania w trakcie pracy wykorzystują `SystemExit` i odzyskiwanie
wygasłych dzierżaw. Nie deklarujemy wykonanego hard OS-kill w trakcie processing,
HA, pomiarów EPS ani produkcyjnego SLO. Nie ma jeszcze retencji ani replay.
Repozytorium nie ma remote: hostowane GitHub Actions pozostaje niezweryfikowane.

Uruchomienie i limity: [obsługa PHASE 2](phase2-operations.md).
Kolejne zadania: [PHASE 3 w planie](implementation-plan.md).

## Rejestr przyrostu

Conventional Commit: `feat: add verified durable event ingestion`.
Identyfikator rewizji: `git log -1 --oneline`. Tożsamość commita ustawiono
wyłącznie dla tej komendy; nie zmieniano globalnej konfiguracji Git.
Nie utworzono remote i nie wykonano push.
