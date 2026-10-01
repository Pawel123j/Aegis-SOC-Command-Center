# Walidacja pierwszych alertów i panelu SOC

Data: 2026-10-01. Zakres częściowy PHASE 4/5/13; pełne fazy pozostają otwarte.
PHASE 3 zakończyła się commit `f0d2ff3` i [643 passed](validation-phase3.md).

## Wykonane kontrole

| Kontrola | Wynik |
| --- | --- |
| Pełna regresja backendu, PostgreSQL/Redis/ClickHouse/Celery | **747 passed**, 580 unit + 167 integration, 318,44 s |
| Coverage procesu testowego | **91%**, uwzględnia gałęzie; nie obejmuje osobno uruchomionych daemonów |
| Ruff lint / format | PASS, 91 plików w chwili pełnej regresji |
| Mypy | PASS, 58 source files |
| Frontend: build TypeScript/Vite | PASS, static bundle bez source maps |
| Frontend: ESLint, Prettier, komponenty/sesja | PASS; **12 testów Vitest**, w tym identyczne ponowienie logu |
| Windows PowerShell parser | PASS |
| Kontrola dodanego endpointu statusu detekcji i regresja alertów | **22 integration passed**, 33,58 s; razem 748 różnych backend tests zweryfikowano w pełnym i końcowym przebiegu |
| Skrypty startowe i SQL mirror | **23 unittest + 1 pytest passed** |
| Audyt zależności frontendowych | PASS, 0 zgłoszonych podatności w aktualnym graph |
| Rzeczywisty daemon detekcji | Przetworzył istniejący event generic_json w izolowanym stacku; checkpoint `processed: 1` |
| Start z folderu w głównym `aegis-soc` | PASS przez launcher w trybie offline, zachowane stare sekrety/volumes, migracje do 0004, readiness 200 |
| Główny panel / assets / CSP | HTTP 200, prawidłowy JavaScript MIME, self-only CSP; ekran login widoczny w przeglądarce |
| Przeglądarka: realny static build przez nginx | Ekran logowania i odmowa dla nieistniejącego konta potwierdzone; hasło wyczyszczone |

Testy backendu potwierdziły wszystkie trzy reguły, checkpoint bez dopasowania,
deduplikację, concurrent workers, restart, hash/schema quarantine, drift
katalogu, rollback audit/alert/checkpoint, RBAC, If-Match, immutable grants,
scope/paginację, czysty rule-test i niezależność od archiwum ClickHouse.
Fixtures detekcji obejmują benign commands, literalne wzmianki o flagach,
błędny Base64, sudo zwykłego polecenia, lokalizację grup i brakujące fakty.

Testy frontendowe kontrolują CSRF i memory-only tokeny, pojedynczy refresh,
terminal 401, brak Web Locks, retry logout podczas 503, If-Match, rozdzielenie
collector/human authority, UI read-only, błąd login, limity czasu i text escaping.

## Odtworzenie

```text
python scripts/bootstrap_env.py --upgrade
cd frontend
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm lint
pnpm format
pnpm test
cd ..
docker compose -f compose.yaml -f compose.offline.yaml --profile test build api tests
docker compose up -d --wait
docker compose --profile test run --rm -e COVERAGE_FILE=/tmp/.coverage tests pytest -q --cov=app -o cache_dir=/tmp/pytest-cache
```

Offline backend wymaga wheelhouse, a offline panel store pnpm. Zwykły online
build nie wymaga tych cache. Kontrole integracyjne tworzą wyłącznie własne,
losowo nazwane bazy i usuwają je w teardown. Izolowany stack używa portu 18080
i osobnego `.env`; główny `aegis-soc` pozostaje pod 8080.

## Otwarte granice dowodu

Próba panelu po zalogowaniu wymaga testowego administratora. Automatyczny
review odrzucił utworzenie tego konta jako zmianę uprawnień; poproszono
o zgodę użytkownika. Dopóki zgoda nie nadejdzie i próba się nie zakończy,
pełny przebieg browser login → ingestion → alert decision jest **niezweryfikowany**.
Nie zastępujemy tego dowodu screenshotem ani mockowanym komponentem.

Hostowane CI nie zostało wykonane. Brak benchmarku, pentestu i produkcyjnej
kwalifikacji. Pełna Sigma, reguły czasowe, incydenty, risk, IOC, SOAR, retencja
i kompletne demo pozostają przyszłym zakresem.
