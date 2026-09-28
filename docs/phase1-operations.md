# PHASE 1 — uruchomienie i obsługa backendu

## Zakres i wymagania

Fundament obejmuje API, migracje PostgreSQL, uwierzytelnianie, role, audyt,
sondy zależności i transport Celery przez Redis. Frontend oraz przetwarzanie
zdarzeń bezpieczeństwa należą do kolejnych faz. Aktualne wyniki kontroli
zawiera [raport walidacji](validation.md).

Wymagane są Python **3.12.14** oraz Docker Engine z Compose v2 i obsługą
kontenerów Linux. `docker version` musi pokazać działający serwer; sama obecność
klienta Docker nie wystarcza. Obrazy aplikacji i CI korzystają z tej samej
wersji Pythona. Na Windows Celery uruchamia się w kontenerze Linux.

## Pierwszy start

Polecenia wykonuj z katalogu głównego repozytorium:

```sh
python scripts/bootstrap_env.py
docker compose config --quiet
docker compose build api
docker compose up -d --wait
docker compose ps --all
```

Generator tworzy prywatny `.env` z losowymi sekretami. Nie wypisuje wartości
i odmawia nadpisania istniejącego pliku. Na POSIX plik powstaje z prawami 0600;
na Windows dziedziczy ACL katalogu. `.env` pozostaje poza Git. Nie publikuj
wyniku `docker compose config` bez `--quiet`, ponieważ zawiera rozwinięte sekrety.

Migrator wykonuje `alembic upgrade head` jako `aegis_owner` przed startem API
i workera. API, worker i bootstrap administratora używają ograniczonego
`aegis_app`. PostgreSQL inicjalizuje rolę aplikacyjną tylko przy pierwszym
uruchomieniu pustego wolumenu; zmiana hasła w `.env` nie zmienia hasła już
istniejącej roli PostgreSQL.

Utwórz pierwszego administratora interaktywnie:

```sh
docker compose exec api python -m app.bootstrap --username admin
```

Hasło podaje się w ukrytym monicie terminala. Nie ma domyślnego konta ani
stałego hasła. Nie przekazuj hasła w argumentach powłoki lub w historii poleceń.

Jedyny port hosta to `127.0.0.1:8080` na reverse proxy. API jest dostępne przez
`http://localhost:8080/api/v1`. Lokalne sondy:

```sh
curl --fail http://localhost:8080/health
curl --fail http://localhost:8080/ready
```

`/health` zwraca stan procesu. `/ready` sprawdza PostgreSQL i wersję migracji,
Redis oraz uwierzytelnione zapytanie ClickHouse; zwraca 503, gdy zależność nie
jest gotowa. Publiczna odpowiedź zawiera jedynie stan łączny. `/metrics` jest
blokowane przez proxy; dostępne jest wewnątrz sieci kontenerów na porcie API.
Awaria lub brak uruchomienia workera jest osobno wykrywany przez test zadania
Celery, a nie przez sondę `/ready`.

## Model uruchomienia

PostgreSQL, Redis i ClickHouse nie publikują portów hosta. Wewnętrzna sieć
`backend` nie zapewnia usługom wyjścia do Internetu. Proxy dołącza również do
sieci `edge`. Bazy korzystają z nazwanych wolumenów; dane nie są zapisywane
w katalogach źródłowych synchronizowanych przez OneDrive.

Kontenery mają wyłączone dodatkowe capabilities i możliwość podniesienia
uprawnień, a system plików jest tylko do odczytu poza wskazanymi wolumenami
i tymczasowymi katalogami. Proces aplikacji działa jako UID/GID 10001.
Obrazy baz korzystają z własnych kont usługowych. Inicjalizację nowych wolumenów
potwierdzono na rzeczywistym Docker Engine w bramce PHASE 1.

Profil `AEGIS_LOCAL_HTTP=true` służy wyłącznie dostępowi przez loopback.
Zewnętrzne wdrożenie wymaga konfiguracji HTTPS i przeglądu granic sieci,
sekretów, kopii zapasowych oraz aktualizacji obrazów. Sama zmiana mapowania
portu nie stanowi wspieranego wdrożenia publicznego.

## Testy i aktualizacja zależności

Przykład przygotowania lokalnego środowiska na Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes -r backend/requirements-dev.lock
.venv/Scripts/python.exe scripts/validate_repository.py
Push-Location backend
../.venv/Scripts/python.exe -m ruff check .
../.venv/Scripts/python.exe -m ruff format --check .
../.venv/Scripts/python.exe -m mypy
../.venv/Scripts/python.exe -m pytest -m "not integration" -p no:cacheprovider --cov=app
Pop-Location
.venv/Scripts/python.exe -m pip_audit -r backend/requirements.lock --strict --require-hashes
```

Na Linux utwórz środowisko przez `python3.12 -m venv .venv` i używaj
`.venv/bin/python` zamiast `.venv/Scripts/python.exe`.
Wyłączenie cache pytest w lokalnym poleceniu omija ograniczenie Windows dotyczące
zmiany uprawnień pliku cache. Nie wyłącza testów ani traktowania ostrzeżeń jako błędów.

Testy integracyjne wykonuj na **oddzielnym, jednorazowym stosie testowym**;
tworzą użytkowników i modyfikują bazę. Poniższy identyfikator projektu tworzy
odrębne kontenery i wolumeny bez kolizji z uruchomionym lokalnym API:

```sh
docker compose -p aegis-soc-validation --profile test build
docker compose -p aegis-soc-validation --profile test run --rm tests
docker compose -p aegis-soc-validation --profile test down
```

Usługa `tests` korzysta z prawdziwych PostgreSQL, Redis, ClickHouse i workera.
Każdy test bazy tworzy osobną bazę `aegis_test_<losowy UUID>`, wykonuje w niej
migrację i usuwa wyłącznie bazę utworzoną przez tę instancję fixture. Nie czyści
tabel aplikacji. Limiter korzysta z Redis DB 1 i unikalnych identyfikatorów klienta;
klucze wygasają po 60 sekundach, bez `FLUSHDB`. Test Celery wysyła nieszkodliwe
zadanie `aegis.ping` przez ten sam broker co worker i usuwa tylko jego wynik.
`AEGIS_DATABASE_URL` zawiera konto aplikacji, a `AEGIS_TEST_DATABASE_URL`
konto właściciela do przygotowania i kontroli stanu testowego. Ustawienie
`AEGIS_INTEGRATION_TESTS=1` wymaga wykonania integracji: brak zależności jest
błędem, nie powodem oznaczenia testu jako pominięty. Testy jednostkowe nie
zastępują tej bramki. `down` zachowuje wolumeny; ponowne użycie tego projektu
nie jest dowodem migracji na pustej bazie.

W CI osobne zadania wykonują kontrole jakości, skan zależności oraz pełny
start Compose i integrację. Usuwanie wolumenów w workflow dotyczy wyłącznie
jednorazowego runnera CI. Obecność workflow w repozytorium nie oznacza,
że uruchomiono go na GitHub.

Lockfile zawierają dokładne wersje i hashe dystrybucji. W środowisku
deweloperskim blokowane są także `pip` i `setuptools`, potrzebne pośrednio
narzędziom budowania i audytu. Po świadomej zmianie `pyproject.toml`:

```sh
python -m piptools compile --allow-unsafe --generate-hashes --no-emit-index-url --output-file=backend/requirements.lock --strip-extras backend/pyproject.toml
python -m piptools compile --allow-unsafe --extra=dev --generate-hashes --no-emit-index-url --output-file=backend/requirements-dev.lock --strip-extras backend/pyproject.toml
```

Wykonuj te polecenia w środowisku Python 3.12 z zainstalowanym dev lockfile.
Oba pliki trzeba przeglądać i testować razem. Nie dodawaj prywatnych adresów
indeksu ani tokenów do lockfile. Weryfikacja dostępności wheel dla Linux
uruchomiona na Windows nie zastępuje budowy i testów kontenera.

## Diagnostyka i zatrzymanie

```sh
docker compose ps --all
docker compose logs --tail=100 api worker
docker compose stop
```

Logi aplikacji są JSON z identyfikatorem żądania i ograniczonym zestawem pól.
Proxy zapisuje tylko metodę, status i identyfikator żądania; jego surowy
error log jest wyłączony, ponieważ Nginx może dołączać do niego pełne URL
i nagłówki. Przy problemach proxy sprawdź stan kontenera, bezpieczny access
log, sondy i konfigurację przez `docker compose exec proxy nginx -t`.

`docker compose down` usuwa kontenery i sieci, zachowując dane. Nie używaj
`down --volumes` na stosie zawierającym dane, które mają pozostać. Kopie,
odtwarzanie i retencja będą rozwijane w dalszych fazach.

## Dowody infrastruktury — 2026-09-28

Potwierdzono Python 3.12.14, instalację zależności z weryfikacją hashy,
budowę obu obrazów, migrację pustej bazy i pełny start Compose na Docker
Engine 29.7.2. Przeszły 230 unit oraz 33 integracje, w tym transport
broker–worker–result backend i test współbieżnego refresh/cofnięcia sesji.
Sondy przez lokalne proxy zwracają 200, a `/metrics` jest przez proxy blokowane.
Wiążący zakres badań i ograniczenia zawiera [raport walidacji](validation.md).

Weryfikacja układu katalogów i kont usługowych opiera się również na
[oficjalnym Dockerfile PostgreSQL 17](https://github.com/docker-library/postgres/blob/master/17/bookworm/Dockerfile)
oraz [entrypoincie ClickHouse](https://github.com/ClickHouse/ClickHouse/blob/master/docker/server/entrypoint.sh).
