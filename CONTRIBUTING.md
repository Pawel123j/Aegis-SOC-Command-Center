# Rozwój i bramki jakości

Status: PHASE 0–3 ukończone; pierwszy przyrost alertów i UI działa od 2026-10-01.
Zakres częściowy faz 4/5/13 opisuje [pierwszy panel](docs/initial-soc.md).
PHASE 1 zweryfikowano 2026-09-28; jej wyniki pozostają historycznym dowodem
fundamentu. Bieżący zakres i wykonane kontrole opisuje [raport walidacji](docs/validation-phase3.md).
Dokumenty zawierają także kontrakty docelowe; obecność implementacji nie oznacza
zaliczenia bramki integracyjnej. Fazy zależne rozpoczynamy po zamknięciu wymaganych kontroli.

## Kolejność

1. Wybierz zadanie z [planu](docs/implementation-plan.md) z ukończonymi zależnościami.
2. Zmień kontrakt/ADR, jeżeli zadanie zmienia decyzję architektoniczną.
3. Dodaj najmniejszy działający przekrój API → domena → storage oraz test ryzyka.
4. Uruchom testy, lint/format i integrację właściwe dla etapu. Zapisz rzeczywiste wyniki.
5. Zaktualizuj dokumentację, macierz wymagań i raport walidacji.
6. Zapisz Conventional Commit: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:` lub `ci:`.

Nie zastępuj nieudanych integracji mockami, aby zgłosić sukces. Testy jednostkowe
mogą używać adapterów in-memory, ale transakcje, blokady, JSONB, migracje i ClickHouse
muszą mieć testy na rzeczywistych usługach. SQLite nie jest substytutem PostgreSQL
w testach integracyjnych. Nie modyfikuj globalnej tożsamości Git użytkownika.

## PHASE 0

`python scripts/validate_repository.py` jest bramką dokumentacji i struktury.
`git diff --check` sprawdza whitespace zmian. Workflow `Phase 0` uruchamia walidator
na PR i push. Uruchomienie lokalne nie potwierdza wyniku GitHub Actions.

## Backend od PHASE 1

Wprowadzone bramki backendu: pytest/coverage, Ruff lint i format check, mypy,
audyt runtime lockfile oraz integracje na prawdziwych PostgreSQL, Redis,
ClickHouse i Celery. Integracje kontrolują migracje, modele, granty i zachowanie
transakcyjne. Python jest przypięty do 3.12.14, a zależności runtime/dev mają
osobne lockfile z hashami. Komendy przygotowania i kontroli zawiera
[obsługa PHASE 1](docs/phase1-operations.md).

PHASE 2 obejmuje źródła i credentiale, single/batch, idempotencję, trwały
inbox/outbox, relay, worker, ograniczone retry, kwarantannę i limity pojemności.
Zmiany tego przepływu wymagają adekwatnych testów rzeczywistej współbieżności,
awarii i odzyskiwania; samo `202` lub `/ready` nie potwierdza przetworzenia
zadania. Stan `staged` oznacza gotowość surowych danych do PHASE 3.
Procedury i ograniczenia: [obsługa PHASE 2](docs/phase2-operations.md).

PHASE 3 obejmuje sześć parserów, niezmienne snapshoty PostgreSQL, osobne
migracje/projekcję ClickHouse, ograniczony AST wyszukiwania i podpisaną paginację.
Zmiany wymagają kontroli formatów, czasu, injection, grantów oraz raw → search
na rzeczywistych bazach, w tym ponowienia po utracie potwierdzenia.
[Obsługa PHASE 3](docs/phase3-operations.md) opisuje zakres i odzyskiwanie.

Frontend ma przypięty TypeScript, ESLint, Prettier i testy Vitest. Komendy:
`pnpm install --frozen-lockfile --ignore-scripts`, `pnpm build`, `pnpm lint`,
`pnpm format`, `pnpm test`. Próba w przeglądarce wymaga rzeczywistego API
i osobnego środowiska z kontem testowym. Pełny zakres fazy 13 pozostaje otwarty.
Skan sekretów oraz dalsze bramki należą do kolejnych etapów.
Każde nowe narzędzie i jego wersję przypinamy przy wprowadzeniu; skaner nie
dostaje sekretów produkcyjnych. Nie ignorujemy błędów przez `continue-on-error`
na bramkach wymaganych.

Workflow `Backend foundation` zawiera osobne zadania jakości i integracji.
Hostowane CI pozostaje niezweryfikowane; lokalny pozytywny wynik nie oznacza
zielonego GitHub Actions. Wyniki i liczby testów zapisujemy z rzeczywistego
wykonania, oddzielnie dla unit i integracji oraz każdej fazy.

Wymagany status PR i ochrona gałęzi to ustawienie hostingu Git: sam plik YAML go nie
włącza. Skonfiguruj regułę ochrony po podłączeniu repozytorium zdalnego. Nie wykonuj
force push. Nie publikuj artefaktów zawierających rzeczywiste logi lub hasła.
