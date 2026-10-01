# Raport walidacji PHASE 3

Data: 2026-10-01. Zakończono normalizację, trwałe snapshoty, projekcję ClickHouse
i wyszukiwanie zdarzeń. Pełna platforma SOC pozostaje rozwijana.
Historyczne dowody: [PHASE 1](validation-phase1.md),
[PHASE 2](validation-phase2.md), [lokalny start](validation-startup.md).

## Wyniki

| Kontrola | Rzeczywisty wynik |
| --- | --- |
| Pełny pytest w Linux/Python 3.12.14 | 643 passed: 497 unit, 146 integration; 198,09 s |
| Coverage tego procesu testowego | 91% statements/branches łącznie; nie obejmuje osobnych procesów API/relay/processor/Celery |
| Parsery i golden fixtures | 75 unit, 13 fixtures; sześć źródeł, Unicode, UTC/DST, formaty uszkodzone i brakujące dane |
| Trwałe przetwarzanie PostgreSQL | 22 integration: atomic snapshot/progress, retry, fencing, crash, kwarantanna, granty i operator recovery |
| Prawdziwy ClickHouse | 11 integration: raw → normalized → search, duplicate projection, utrata ACK, filtry, actor/target, kursory, granty i migracje |
| Ruff lint/format | passed; 79 plików Python w kontroli formatowania |
| mypy strict | passed; 50 source files, cache poza OneDrive |
| Skrypty stdlib | 23 unittest passed; zachowanie poprzednich sekretów, runtime check i offline wheelhouse |
| Kopie SQL | kontrola zgodności obu migracji backend/infra passed |
| Obrazy | runtime/test Linux amd64 z lockfile i lokalnych kół z hashami; bez wyłączenia TLS |
| Świeży Compose | wymagane usługi gotowe; Alembic 0003 i dwie migracje ClickHouse zastosowane |
| Rzeczywisty runtime smoke | relay/worker/processor → projected → GET event z archiwum passed |
| Launcher | składnia PowerShell poprawna; ograniczona czasowo sonda Docker: true w 797 ms |

Runtime smoke utworzył w osobnym projekcie `aegis-phase3-20261001` własnego
administratora z losowym hasłem Unicode i syntetyczne źródło. Jedno zdarzenie
przyjęto idempotentnie, znormalizowano, zapisano i odczytano z ClickHouse.
Po kontroli: raw=1, normalized=1, pipeline=1, projected=1; włączone źródła=0,
aktywne credentiale=0, aktywne sesje=0. Dane użytkownika znajdowały się w osobnym
projekcie `aegis-soc` i nie służyły jako fixture testów.

Regresja wykryła różnicę kanonizacji IPv4 mapped IPv6 na Windows/Linux,
obsługę sufiksu SSH publickey i natywne sortowanie UUID ClickHouse. Poprawiono
wspólną kanonizację oraz jawne sortowanie UUID jako tekst i identyczny warunek
kursora. Testy potwierdzają odczyt przed background merge i brak zawyżania liczników.
Naprawiono też izolację konfiguracji nowych testów od środowiska Compose.

Docker Desktop początkowo nie uruchamiał silnika przez uszkodzone tymczasowe
endpointy AF_UNIX. Przy zatrzymanym Desktop zachowano katalogi połączeń pod
nowymi nazwami i pozwolono odtworzyć je aplikacji. Istniejące kontenery i woluminy
pozostały zachowane; nie wykonywano resetu ani prune.

## Odtwarzanie

```sh
python scripts/bootstrap_env.py
docker compose -f compose.yaml -f compose.offline.yaml --profile test build api tests
docker compose up -d --wait
docker compose --profile test run --rm -e COVERAGE_FILE=/tmp/.coverage tests pytest -q --cov=app -o cache_dir=/tmp/pytest-cache
```

Tryb offline wymaga wcześniej przygotowanej biblioteki kół:
`python scripts/prepare_wheelhouse.py`. Bez niej standardowy build online to
`docker compose --profile test build api tests`.
Istniejący `.env` uzupełnia `python scripts/bootstrap_env.py --upgrade`.
Testy tworzą własne bazy PostgreSQL/ClickHouse o losowych nazwach i usuwają tylko je.

## Granice dowodu

Nie wdrożono jeszcze automatycznej retencji, detekcji, alertów ani UI w zakresie
tej fazy. Zachowane raw i snapshoty wciąż zajmują pojemność; limity raw nie są
limitem fizycznej pamięci baz. Wyszukiwanie ma opóźnioną spójność i jawne limity
czasu, zasobów oraz zakresu. Nie wykonano benchmarku ani zewnętrznego pentestu.
Runtime dependency lock pozostał bez zmian; wcześniejszy audyt opisuje raport
PHASE 2. Hostowane GitHub Actions nadal pozostaje niezweryfikowane.
