# Rozbudowa Aegis — audyt i plan etapów

Data: 2026-10-01. Punktem wyjścia jest commit `6119335` i działający panel
pod `http://localhost:8080`. Nowe wymagania użytkownika wyznaczają kolejność
poniższych 15 etapów. Rozbudowa zachowuje istniejący system; wcześniejszy
[plan PHASE 0–20](implementation-plan.md) pozostaje rejestrem historycznym
i źródłem dodatkowych kryteriów jakości.

## Audyt przed implementacją

| Obszar | Stan odczytany z kodu | Konsekwencja dla rozbudowy |
| --- | --- | --- |
| Repozytorium | Modularny backend `backend/app/modules`, osobne routery, migracje Alembic; React/TypeScript/Vite w `frontend/src` | Dodawać moduły domenowe, bez przepisywania aplikacji |
| Modele danych | PostgreSQL: użytkownicy, sesje, audyt, inbox/outbox, normalized snapshots, checkpointy detekcji, alerty i deployments | Incydenty i ich historia należą do PostgreSQL |
| API | FastAPI `/api/v1`, jawne permissions, walidacja Pydantic, bezpieczne błędy, limity, `If-Match` dla decyzji | Zachować kontrakty i sprawdzać uprawnienia na backendzie |
| Frontend | Panel prawdziwych API, filtrowana nawigacja, obsługa loading/error/empty, tokeny w pamięci, dowody eventu | Dodać listę i szczegóły incydentu; użyć istniejącego widoku dowodu |
| Detection engine | Trzy czyste reguły single-event, osobny daemon, alert/audit/checkpoint w jednej transakcji, deduplikacja | Automatyczny incydent zapisać w tej samej transakcji; korelacja sekwencji to następny etap |
| Przechowywanie dowodów | Niezmienne snapshoty normalized event i alertu w PostgreSQL; ClickHouse jest projekcją wyszukiwania | Sprawa używa zachowanych dowodów; awaria archiwum nie usuwa historii analityka |
| Testy | Unit oraz integracje na własnych losowych bazach PostgreSQL i rzeczywistych Redis/ClickHouse; Vitest dla sesji i komponentów | Dodać przypadki ról, retry, wyścigów, izolacji replay i rollbacku audytu |
| Docker | Usługi API, relay, worker, processor, detector, migratory, proxy; dane w volumes, port 127.0.0.1:8080 | Nowy moduł nie potrzebuje nowej usługi ani bazy; migracja przed startem API |
| Stan weryfikacji | Poprzednio 748 różnych testów backendowych i 12 frontendowych; pełny zalogowany przebieg przeglądarkowy otwarty | Nowy przyrost wymaga własnej regresji; wcześniejszych wyników nie przedstawiać jako nowych |

Miejsca wymagające korekty: wspólna autoryzacja mutacji nie powinna być
importowana z routera alertów; po oczekiwaniu na blokadę trzeba ponownie
sprawdzić aktualną rolę i ważność sesji. Dokumentacja zawiera również stare
zapowiedzi braku frontendu i normalizacji — należy wskazać rzeczywisty stan.

Istotna własność źródeł: każde źródło live otrzymuje osobny `dataset_id`,
a `run_id` live jest zerowym UUID. Sprawa operacyjna w jednej organizacji
musi móc objąć wiele źródeł. Zachowuje więc pochodzenie każdego alertu;
replay pozostaje odizolowany według dataset i run. Zmiany tej zasady oraz
pięć statusów z nowej prośby opisuje
[ADR 0007](adr/0007-incident-case-management.md).

## Kolejność dostarczania

| Etap | Działający przyrost | Główna bramka |
| --- | --- | --- |
| 1 — Incident Management | Model sprawy, alerty, owner, status, severity, tagi, notatki, dowody, historia i UI; automatyczne sprawy z nowych High/Critical alertów | API + migracja + RBAC + atomowość + UI + regresja |
| 2 — Correlation Engine | Trwałe reguły sekwencji/threshold z event time, oknami, AND/OR i kluczami encji; przykładowe reguły | Granice czasu/liczników, late events, restart, replay i false joins |
| 3 — Risk Engine | Osobny deterministyczny moduł 0–100, wersja, wejścia i jawne wkłady `risk_explanation` | Ręcznie policzone fixtures, brak podwójnego naliczania, nieznane dane |
| 4 — MITRE ATT&CK | Lokalny wersjonowany katalog tactics/techniques, walidacja mapowań i coverage API/UI | Zgodność ID i liczników z rzeczywistymi alertami/sprawami |
| 5 — Sigma | Bezpieczny import YAML, ograniczony kompilator equals/contains/startswith/endswith/AND/OR/NOT i wersjonowanie | Odrzucanie nieobsługiwanych konstrukcji, fixtures, wykonanie przez daemon |
| 6 — Entity Profiles | Users, hosts, IPs, processes: aktywność, alerty, sprawy, first/last seen i objaśnione ryzyko | Stabilna tożsamość encji i ograniczone zapytania |
| 7 — Threat Intelligence | Lokalna baza IP/domain/URL/hash i interfejs providerów, reputacja, dowód dopasowania | Normalizacja IOC, uprawnienia, brak niezamierzonych wywołań URL |
| 8 — Attack Timeline | Graficzna chronologia zaobserwowanych eventów z oryginalnymi dowodami | Late events, prawdziwy czas zdarzenia i oddzielenie hipotezy od faktu |
| 9 — UEBA | Baselines/statystyki, wynik anomalii, observed/baseline/explanation | Cold start, strefy czasu, replay isolation, powtarzalność |
| 10 — Mini SOAR | Playbook, trwałe run/step history, retry i domyślna symulacja akcji infrastrukturalnych | Restart nie powtarza skutków; brak rzeczywistych blokad domyślnie |
| 11 — Dashboard | Agregacje ostatnich 24h, encji, rules, MITRE/risk/severity i ingestion rate; SSE jeśli uzasadnione | Prawidłowe zakresy live/replay, limity i aktualizacje prawdziwych danych |
| 12 — Audit Log | UI istniejącego audytu i kompletne działania nowych modułów | Transakcyjne powiązanie działania z audytem, append-only |
| 13 — RBAC | Rozwinięcie istniejącej macierzy Admin/Analyst/Viewer i zarządzania użytkownikami | Backend odrzuca zabronione operacje wszystkich modułów |
| 14 — Notifications | Kanały/provider interfaces, env secrets, trwały delivery history/retry | Kontrolowane wysyłanie, redakcja sekretów, błędy i ograniczenia sieci |
| 15 — Reporting | Raport utrwalonej sprawy, timeline, dowody, notes, actions i wersje ocen | Spójny snapshot, redakcja, raport dla analityka i osoby nietechnicznej |

Kontrolowany generator demo emituje surowe logi przez ingestion, z własnym
dataset/run i seed. Scenariusz rozszerza się wraz z gotowymi modułami;
nie zapisuje gotowych alertów, ocen ani spraw bezpośrednio do bazy.

## Zasady odbioru

Każdy przyrost ma rzeczywisty model, API, walidację, testy i frontend.
Widoczność w nawigacji wymaga działającego backendu. Po większej części
uruchamiamy dotychczasową regresję, lint, typy, build i migracje, a wynik
oraz granice dowodu zapisujemy w osobnym raporcie.

Etap 1 przechowuje pola `risk_score` i `confidence` jako nullable.
Brak silnika ryzyka albo skalibrowanej oceny confidence oznacza brak wyniku,
a nie losową liczbę lub zero. Automatyczna sprawa jest kandydatem do oceny
analityka; sama w sobie nie potwierdza ataku.

Na końcu etapu raport zawiera implementację, dodane/zmienione pliki,
endpointy, modele, nowe testy, wynik kontroli, ograniczenia i następny krok.
Zmiany zapisujemy w osobnych logicznych commitach.

## Dostarczone przyrosty i bieżąca walidacja

Etap 1: [sprawy i praca analityka](validation-incidents.md), commit `4db94e8`.
Etap 2: [reguły korelacji](validation-correlation.md), osobny proces, trwały
watermark i manifest replay, wiele dowodów oraz panel reguł.
Zakres czasu i tożsamości określa [ADR 0008](adr/0008-temporal-correlation.md).
Jest to rozpoznawanie jawnych sekwencji, a nie cały historyczny graf/merge
PHASE 6. Etap 3: [ocena ryzyka](validation-risk.md), deterministyczna punktacja,
historia i jawny brak przyszłego kontekstu. [ADR 0009](adr/0009-explainable-risk.md)
określa zasady. Etap 4: [lokalny katalog i coverage MITRE](validation-mitre.md),
osobne historyczne mapowania oraz nazwy w panelu.
[ADR 0010](adr/0010-versioned-attack-mappings.md) oddziela skojarzenie
techniki od potwierdzenia ataku. Kolejny przyrost: Sigma.
