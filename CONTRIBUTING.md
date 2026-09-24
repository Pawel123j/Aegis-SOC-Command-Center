# Rozwój i bramki jakości

Status repozytorium: PHASE 0. Dokumenty opisują kontrakty docelowe; nowe funkcje
oznaczamy jako zaimplementowane dopiero po sprawdzeniu ich działania.

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

## Od PHASE 1

Planowane narzędzia: pytest/coverage, Ruff lint i format check, sprawdzanie typów,
Alembic upgrade na czystej i poprzedniej bazie, skan zależności i sekretów.
Frontend: TypeScript, ESLint, testy komponentów oraz E2E z prawdziwym API.
Każdy tool/wersja będzie przypięty przy wprowadzeniu; skaner nie dostaje sekretów
produkcyjnych. Brak ignorowania błędów przez `continue-on-error` na bramkach wymaganych.

Wymagany status PR i ochrona gałęzi to ustawienie hostingu Git: sam plik YAML go nie
włącza. Skonfiguruj regułę ochrony po podłączeniu repozytorium zdalnego. Nie wykonuj
force push. Nie publikuj artefaktów zawierających rzeczywiste logi lub hasła.
