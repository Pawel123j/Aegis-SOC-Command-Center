# Walidacja Etapu 2 — Correlation Engine

Data: 2026-10-01. Punkt wyjścia: `4db94e8`.
Stan: implementacja, pełna regresja, migracja i główny start zweryfikowane.
Zalogowany workflow przeglądarkowy pozostaje otwarty. [Plan](soc-expansion-plan.md),
[decyzja semantyczna](adr/0008-temporal-correlation.md).

## 1. Zakres

Natywne reguły liczą zdarzenia w oknie czasu i rozpoznają kolejność etapów.
Finalny alert zachowuje dowody wszystkich składających się na niego zdarzeń.
Nowe High/Critical alerty tworzą incydent w istniejącym module. Osobny proces
korelacji korzysta z niezmiennego archiwum PostgreSQL oraz trwałych checkpointów.
Pięć przykładów obejmuje próg porażek, porażki→sukces, PowerShell→network,
logowanie→zmianę grupy oraz pełny pięcioetapowy ciąg z dziewięcioma dowodami.
AND/OR, same_user/host/ip/process, licznik oraz maksymalny span są jawne.
Znane sprzeczne sesje/SID i niezgodny trwały proces wykluczają łączenie.
Windows rozróżnia konto logowania, wykonawcę zmiany i konto docelowe.
Panel pokazuje katalog, enabled/version, izolowany test, wyniki pokrycia
i dowody alertów/spraw. Pole kotwicy zachowuje zgodność wcześniejszych alertów.

## 2. Dodane i zmienione pliki

Dodano: `backend/app/api/correlations.py`, `app/correlator.py`,
`app/modules/alerts/evidence.py`, moduły korelacji
`admission/builtin/contracts/engine/models/persistence/processing/replay.py`,
`migrations/versions/0006_correlation.py`, unit `test_correlation_engine.py`,
integration `helper_correlation.py`, `test_correlations.py`,
`test_correlation_security.py`.

Zmieniono: composition root, config, readiness, modele/schematy/router alertów,
detector selection własnego katalogu, modele/schematy/projekcje incydentów,
import modeli migracji i testy storage. Zachowano trzy reguły single-event.
Filtr alertów po source/dataset obejmuje także wszystkie contributed snapshots.

Frontend: nowe małe komponenty w `src/detections/` i `src/evidence/`, fixtures
i `correlations.test.tsx`; App/API/types/Alerts, widoki alertów, dowodów i osi
incydentów. Naprawiono race spóźnionego authority response po logout oraz
pozostawianie poprzedniego dowodu po błędzie sesji i zmianie osoby.
Uruchomienie: `compose.yaml`, `compose.offline.yaml`, `.env.example`,
nowy proces `app.correlator`
na tym samym obrazie backendu. Dokumentacja: ten raport oraz ADR 0008.
Aktualizacje README backendu/frontendu/infrastruktury, architektury,
API/data model, correlation-engine, indeksów ADR/validation oraz obu planów
i macierzy wymagań. Lockfile i zależności pozostają bez zmian.

## 3. Endpointy

Pod `/api/v1`: GET `/correlations`, GET `/correlations/{rule_id}`,
PATCH `/correlations/{rule_id}` z If-Match, POST `/correlations/test`,
GET `/correlations/status`, POST `/correlations/replay/finalize`.
Read/test/publish używa istniejącej macierzy detections permissions.
Mutacja ponownie sprawdza rolę i ważność sesji po blokadzie oraz zapisuje audyt
w tej samej transakcji. Viewer nie testuje ani nie publikuje; collector nie
otrzymuje uprawnień ludzkiej sesji. Czysty test maksymalnie 100 eventów odrzuca
duplikaty ID i nie zapisuje efektów domenowych.
Replay finalize przyjmuje dataset/run oraz expected_event_count 1–10000,
niezerowy run, pełną normalizację i dokładny licznik; retry zgodnej finalizacji
zwraca ten sam manifest. Nie tworzy nowych źródeł replay.

## 4. Modele i migracja

`0006_correlation`: CorrelationScope i CorrelationJob oraz rozszerzenie Alert
o immutable `event_snapshots`; backfill poprzednich alertów zachowuje jeden dowód.
Scope ma watermark, sealed_at, manifest/hash oraz deployment_snapshot/hash.
Job ma namespace, event time, hashe kluczy encji, stan, błąd i evaluated_rules.
Indeksy pokrywają scope/time oraz używane grupy encji. Runtime ma SELECT/INSERT
i tylko wskazane mutable kolumny zadań/zakresu; nie ma DELETE/DDL ani UPDATE
dowodów. Trigger blokuje cofanie watermark oraz zmianę zamkniętego manifestu
i konfiguracji. Walidacja dopinania odrzuca pusty/uszkodzony dowód korelacji,
zamiast używać legacy fallback.
Znane SID i sesje są sprawdzane przed wyborem minimalnego deterministycznego
dowodu, aby nowszy niepasujący login nie ukrył wcześniejszego poprawnego.

Downgrade z istniejącymi alertami korelacji odmawia usunięcia ich katalogu przez
FK i wycofuje transakcję; nie spłaszcza ani nie usuwa historycznych dowodów.
Risk/confidence pozostają NULL. Incydent używa czasu i encji wszystkich dowodów.

## 5. Nowe testy

Testy obejmują liczniki i sekwencje, granice czasu, kolejność dostarczenia,
silne tożsamości, live/replay, backlog, retry, niezmienność dowodów i audyt.
Dodano **25 unit + 18 primary integration + 31 independent security integration**,
łącznie 74 nowe przypadki backendu, oraz **15** frontendowych.
Integracje przechodzą przez prawdziwe ingestion i normalizację, badają watermark
i otwartą transakcję admission, duży backlog, 500/501 kandydatów, replay seal
i zmianę deploymentu, brak backfill live, współbieżnych workerów, retry po
rollbacku sprawy/audytu, wiele źródeł, granty oraz sześć uszkodzeń dowodów.
Przykład Windows obejmuje rzeczywiste 4625/4624/4732 i cały dziewięcioeventowy
ciąg. Kolejność, progi i okna mają dodatnie oraz ujemne próby kontrolne.
Frontend sprawdza konflikty wersji, drafts, uprawnienia, błędy, komplet dowodów,
UTF-8 limits, stan pokrycia i odrzucenie spóźnionych odpowiedzi sesji.

## 6. Wykonane kontrole

| Kontrola | Wynik |
| --- | --- |
| Testy skryptów | 23 unittest passed |
| Docker po ponownym uruchomieniu | Engine 29.7.2, dotychczasowe usługi healthy |
| Test SQL migracji archiwum | 1 pytest passed |
| Nowe unit evaluatora | 25 passed |
| Focused real PG | 82/84 passed w pierwszym przebiegu 77,79 s; dwa błędy przygotowania testów naprawione, ich rerun: 2 passed / 16 deselected, 20,32 s |
| Frontend | 38/38 passed; TS, lint, format i produkcyjny build PASS |
| Ruff lint/format | PASS, 116 plików |
| Mypy | PASS, 76 source files |
| Pełna regresja i coverage | **894 passed**, 644 unit + 250 integration, **516,22 s**; **91%** branch/process coverage na Linux/Python 3.12.14 |
| Fresh Compose | PASS, nowy projekt aegis-correlation-20261001, 0006, API/bazy healthy i proces korelacji uruchomiony |
| Główny start nowej wersji | PASS przez oficjalny launcher offline/SkipAdmin; upgrade 0005→0006, readiness 200, usługi uruchomione |
| Main HTTP/OpenAPI/panel | PASS; health/ready 200, wszystkie pięć ścieżek/sześć operacji korelacji, JS 200 application/javascript, self-only CSP |
| Restart głównego procesu korelacji | PASS; proces ponownie uruchomiony, pozostał aktywny przez ponad 5 min, log bez błędów |
| Zgodność obrazu testowego i main | PASS; normalized source SHA-256 `691a092596e64c3adf490a06befa432d8ba9546c7a34e5cab3a7379c0bd4caeb` |
| Sprzątanie baz integracyjnych | PASS; po pełnej regresji 0 baz `aegis_test_*`, 0 kont UI w odrębnym środowisku |
| Kontrola repozytorium | PASS; 259 plików tekstowych, 43 katalogi, 37 wymagań, 8 ADR oraz `git diff --check` |

Główna baza przed i po upgrade miała 0 users/raw/normalized/alerts/incidents;
migracja zmieniła 0005 na 0006. Sekrety i volumes zachowano. Nie zastąpiono
tego pustego stanu gotowymi alertami demo. Publiczny ekran wymaga pierwszego
administratora ustawionego przez użytkownika w zwykłym launcherze.

Pełny wynik zawiera wszystkie 74 nowe przypadki oraz wcześniejsze 820,
w jednym wspólnym przebiegu. Coverage jest jednym pomiarem procesu testowego,
nie sumą oddzielnych kontroli. Osobne daemony nie są instrumentowane tym pomiarem.
Nie wprowadzono nowych zależności ani zmiany lockfile.

Odtworzenie po przygotowaniu panelu i usług:

```text
docker compose -f compose.yaml -f compose.offline.yaml --profile test build api tests
docker compose up -d --no-build --wait
docker compose --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests pytest -q -p no:cacheprovider --cov=app --cov-report=term --tb=short
cd frontend
pnpm build
pnpm lint
pnpm format
pnpm test
```

Main sprawdza oficjalny launcher offline z `-SkipAdmin`, bez tworzenia kont:
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/aegis.ps1 -Action start -SkipAdmin -BuildMode offline`.
Puste środowisko wymaga pierwszego konta ustawionego przez użytkownika przez
zwykły launcher; nie ma stałego hasła demo.

Testy wykonano w odrębnym stosie na porcie 18081 z własnymi sekretami i volumes.
Każda integracja tworzy dodatkowo własną losową bazę `aegis_test_<UUID>`
i usuwa ją w teardown. Po testach potwierdzono brak pozostałych baz integracji.
Po weryfikacji zatrzymano oba stosy testowe na 18080 i 18081, zachowując dane.
Główna aplikacja na 8080 pozostała uruchomiona.
Nie tworzono konta UI w głównym ani nowym środowisku. Hosted CI i zalogowany
workflow przeglądarkowy nie są częścią powyższego wyniku.

## 7. Napotkane problemy

Docker Desktop ponownie nie wystartował przez niedostępny endpoint AF_UNIX
`Docker/run/dockerInference`. Po potwierdzeniu zatrzymania wszystkich procesów
Docker odłożono tylko dwa katalogi komunikacji do zachowanych kopii:
`run.aegis-correlation-backup-18caf5d1d18c42e68a0552333c3495e2` oraz
`docker-secrets-engine.aegis-correlation-backup-4928e8724b724a0198bc94c558910fa5`.
Ponowny start przywrócił silnik i usługi. Nie wykonywano resetu ani kasowania
baz lub volumes. Błąd oraz wykonane działania są lokalnym dowodem z logów.
Przegląd poprawił niezgodne pole grupy Windows, błędne użycie aktora SYSTEM
zamiast konta logowania, SID placeholder/konflikt, wybór wcześniejszej zgodnej
sesji/procesu oraz zamrożenie deploymentu w replay. Dowody walidują komplet,
unikalność, hash i obecność zgodnej kotwicy. Outbound wymaga jawnej akcji albo
direction, zamiast dopowiadania kierunku dowolnego połączenia.

Pierwsze wykonanie integracji wychwyciło dwie usterki fixture: wirtualny przyszły
czas worker/API był niezgodny oraz helper normalizacji nie uwzględniał dwóch
claims na event. Ujednolicono zegar testu i ograniczoną pętlę przygotowania,
zachowując pełne asercje i kod produkcyjny. Test kontrolowanej wolnej budowy
schematu aplikacji otrzymał większy deadline 45 s, zachowując sprawdzanie
serializacji i rzeczywistego overlap workerów.

## 8. Ograniczenia

Graf i scalanie już obsługiwanych spraw, pełna Sigma, scoring i generator demo
pozostają dalszymi etapami. Nie deklarujemy wykrycia potwierdzonego ataku.
Risk/confidence pozostają NULL. Do testu ręcznego panelu po zalogowaniu nadal
brakuje osobnej zgody na tymczasowe konto administratora w bazie testowej;
wcześniejsza automatyczna kontrola odrzuciła tę zmianę uprawnień.
Główne środowisko zachowuje istniejące konta. Hostowane CI nie było wykonywane.
Live ma 120 s bufora, toleruje przyszły czas tylko do 30 s, a końcowe late/
clock_skew/incomplete nie są publicznie ponawiane. Bariera dowolnego nieznanego
backlogu jest konserwatywna; brakujące wejście replay może również blokować live.
Minimalny dowód nie jest pełną listą zdarzeń z okna; kolejne kotwice mogą dawać
odrębne alerty bez suppression. Explorer nie ma jeszcze filtrów rule/MITRE
annotations. Host/process ID muszą mieć wiarygodne pochodzenie ze źródła.

## 9. Następny krok

Po zaliczeniu bieżącego przyrostu: Etap 3 — deterministyczny Risk Engine
z wersją, zakresem 0–100 i jawnym `risk_explanation`.
