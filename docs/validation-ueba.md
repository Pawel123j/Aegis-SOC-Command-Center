# Walidacja Etapu 9 — UEBA

Data: 2026-10-07. Punkt wyjścia: `992d3c9`.
Stan: etap wdrożony lokalnie; regresja, jakość i kontrola uruchomienia/restartu
PASS. Zalogowany browser E2E i pozostałe granice opisuje punkt 8.
[Zakres](ueba.md), [ADR 0015](adr/0015-observed-behavior-baselines.md).

## 1. Zakres

Profil użytkownika lub hosta porównuje zakończoną dobę UTC z 28 poprzednimi.
Sześć wskaźników wykrywa nową godzinę/IP/host logowania, pierwsze narzędzie
administracyjne oraz wzrost nieudanych logowań i aktywności. Każdy ma score,
wyjaśnienie, baseline, observed value oraz oryginalne dowody. Brak historii,
niepewny czas, niepełny indeks i brak faktów uprawnień pozostają jawne.

Windows bez rozpoznanego target nie przypisuje logowania do konta SYSTEM.
Dowód otwiera zweryfikowany dokument PostgreSQL, po ponownym sprawdzeniu
obecności UUID i hash w bieżącej analizie. Zmiana dnia lub sesji usuwa stary
wynik; live i poszczególne replay mają odrębne historie.

## 2. Dodane pliki

Łącznie 18 nowych plików:

- `backend/app/api/ueba.py`
- `backend/app/modules/ueba/__init__.py`
- `backend/app/modules/ueba/queries.py`
- `backend/app/modules/ueba/schemas.py`
- `backend/app/modules/ueba/statistics.py`
- `backend/app/modules/ueba/views.py`
- `backend/tests/integration/test_ueba.py`
- `backend/tests/unit/test_ueba.py`
- `backend/tests/unit/test_ueba_evidence.py`
- `docs/adr/0015-observed-behavior-baselines.md`
- `docs/ueba.md`
- `docs/validation-ueba.md`
- `frontend/src/ueba/UebaProfile.tsx`
- `frontend/src/ueba/filters.ts`
- `frontend/src/ueba/types.ts`
- `frontend/src/ueba/ueba.css`
- `frontend/tests/ueba.test.tsx`
- `frontend/tests/uebaFixtures.ts`

## 3. Zmienione pliki

Łącznie 16 istniejących plików:

- `README.md`
- `backend/app/main.py`
- `compose.yaml`
- `docs/adr/README.md`
- `docs/api-contract.md`
- `docs/architecture.md`
- `docs/data-model.md`
- `docs/entities.md`
- `docs/implementation-plan.md`
- `docs/repository-structure.md`
- `docs/requirements-traceability.md`
- `docs/security.md`
- `docs/soc-expansion-plan.md`
- `docs/validation.md`
- `frontend/src/entities/EntityProfile.tsx`
- `scripts/repository_manifest.json`

Rejestracja routera i karta profilu łączą backend z panelem. Compose używa
obrazów `ueba-stage9`. Dokumentacja i manifest opisują aktualny zakres.

## 4. Endpointy

- `GET /api/v1/entities/{entity_id}/ueba?day=YYYY-MM-DD&mode=live`.
- `GET /api/v1/entities/{entity_id}/ueba/events/{event_id}` z tym samym
  dniem/zakresem i wymaganym `document_sha256`.

Replay wymaga dokładnego dataset/run. Wymagane łącznie events:read,
alerts:read i incidents:read. Oba odczyty mają no-store i współdzielą 30/min.
SQL 3 s, najwyżej 2000 unikalnych zdarzeń i 8 MiB dowodów. Anomalia pokazuje
do 25 dowodów i ich pełną liczbę. Nie ma ukrytego samplingu statystyk.
Zmiana dowodu daje 409 ueba_changed; niespójność lub limit osobne błędy 409.

## 5. Modele

UebaFilters/UebaEvidenceFilters, UebaEntity, UebaScope, Observation, Baseline,
Evidence, Indicator i UebaReport są DTO. VerifiedEvent reprezentuje sprawdzony
oryginał. Źródłem pozostają EntityIdentity/Observation/IndexReceipt oraz
RawEvent/NormalizedEvent. Nie dodano tabeli ani migracji; head 0011_intelligence.
Polityka `ueba-statistics-v1` jest deterministyczna dla tego samego zbioru danych.
GET nie zapisuje baseline, nie publikuje alertów i nie zmienia ryzyka spraw.

## 6. Nowe testy

119 testów backendu: 48 statystyk/kontraktu, 32 integralności dowodów,
39 integracyjnych. Obejmują UTC i granice okien, minima historii i grup
zdarzeń, zero dni, progi, role logowania, jakość czasu, deduplikację,
replay, receipts, limity i trzy uprawnienia. Realne ingestion/parser/API
sprawdza brak target Windows. Otwieranie dowodu działa bez ClickHouse,
odrzuca niewłaściwy hash, dzień, UUID i zdarzenia bez anomalii.

48 nowych testów panelu kontroluje zapytania, dzień UTC, stany bez historii,
wyjaśnienia, dowody, błędy, sesję i odrzucanie spóźnionych odpowiedzi.

## 7. Wyniki kontroli

Pełna regresja backendu: **2181 PASS** na Linux/Python 3.12.14, w rozłącznych
partiach pokrywających całą zebraną listę. 1500 unit i 681 integracyjnych.
Nie jest to deklaracja jednego procesu z całym zestawem. Dwie pierwsze
partie wykonano przed ostatnią poprawką przypisania su; końcową wersję całego
modułu UEBA sprawdzono dodatkowo kompletem 119 testów z pokryciem.
Pozostałe partie oraz 1500 unit wykonano z końcowym kodem.

| Partia | Wynik |
| --- | --- |
| integration-1 | 171 PASS; 360.84 s |
| integration-2 | 170 PASS; 332.04 s |
| integration-3 | 170 PASS; 264.10 s |
| integration-4 | 170 PASS; 309.87 s |
| unit | 1500 PASS; 36.60 s |

| Pozostała kontrola | Wynik |
| --- | --- |
| Nowy moduł i pokrycie | 119 PASS, 144.70 s; **99%** Python modułu/routera, 279 statements i 54 branches; nie jest to pokrycie wnętrza SQL ani całego systemu |
| Frontend | **286 PASS**, 12 plików, 20.62 s; TypeScript, ESLint i Prettier PASS |
| Backend jakość | Ruff PASS, 206 plików format PASS; mypy 131 plików PASS w Linux |
| Zależności | Offline lockfile z hashami, pip check PASS; zgodność zależności, bez deklaracji aktualnego audytu podatności |
| Kompilacja panelu | 104 moduły, 1.24 s; JS index-s6LtqeiL.js 444.56 kB / gzip 124.14; CSS index-Byy-Fi2J.css 22.29 kB / gzip 5.65 |
| Oddzielna instalacja | Nowe bazy, migracje 0011, health/ready/OpenAPI/panel/assets 200, anonimowy raport 401, CSP self |
| Główna instalacja | Oficjalny launcher offline z SkipAdmin, zachowane liczności i plik env, zgodny kod, restart processor/detector/correlator i HTTP PASS |
| Repozytorium | 451 plików tekstowych, 47 katalogów, 21 faz, 37 wymagań, 15 ADR; linki/składnia/format i git diff --check PASS |

Hash kodu app/migrations/katalogu, zgodny z uruchomioną wersją:
`205d6380ad70929adb8ce2eeed93a4089fb209f95fd824f53ed05b10f999d9f9`. Nie jest to hash całego repozytorium ani obrazu.
Dowody lokalne zapisano w ignorowanym `.local/ueba/`; zawierają wyniki partii,
kontrole stanu, zasobów HTTP oraz restartu. Nie są wynikiem hostowanego CI.

Po testach potwierdzono zero baz `aegis_test_%` zarówno w głównej, jak i
odrębnej instancji PostgreSQL. Zatrzymano projekt `aegis-ueba-20261006`,
zachowując jego wolumeny. Główna instalacja pozostaje uruchomiona; healthcheck
mają API, PostgreSQL, Redis i ClickHouse, a pozostałe procesy potwierdzono jako
running. Stan główny nadal ma zero kont i danych domenowych oraz jeden deployment TI.

## 8. Problemy i granice dowodu

Docker Desktop wielokrotnie zatrzymywał się pomiędzy wznowieniami pracy.
Po zwykłym starcie potwierdzono błąd dockerInference. Katalogi komunikacyjne
odłożono do kopii i uruchomiono silnik; nie usunięto wolumenów ani danych.
Naprawa przywróciła start w tej sesji; nie dowodzi trwałego usunięcia błędu
Docker Desktop przy każdym przyszłym restarcie.

Pierwszy pomiar coverage i kontrola Ruff zatrzymały się na zapisie cache do
read-only /app. Poprawiono lokalne polecenia walidacji, kierując cache do /tmp;
końcowe kontrole PASS. Windows mypy nie miał dostępnych stubów PyYAML;
końcowy pełny check wykonano w docelowym obrazie Linux. Jeden frontend run
przerwał błąd ENOENT tymczasowego katalogu sandboxu; powtórzenie z własnym
katalogiem TEMP/TMP dało 286 PASS. Wcześniejsze 68 testów UEBA PASS były
kontrolą pośrednią, nie zastępują końcowych 119.

Wcześniejsza automatyczna kontrola odrzuciła tworzenie administratora głównej
instalacji jako zmianę uprawnień. Nadal używamy SkipAdmin; pierwsze konto
użytkownik tworzy lokalnym launcherem. Zalogowany browser E2E pozostaje
otwarty. Konta testów istnieją wyłącznie w izolowanych bazach fixtures.
Internetowy audyt zależności oraz hostowane CI pozostają odrębne i otwarte.

Analiza jest obliczana na żądanie i może zmienić się po przyjęciu późnych
logów. Score nie jest prawdopodobieństwem ataku, a brak odchyleń nie dowodzi
bezpieczeństwa. Uprawnienia administratora pozostają nieznane bez źródłowego
faktu; dzienne okna UTC nie modelują lokalnych zmian ani świąt. Członkostwo
opiera się na append-only indeksie chronionym grantami i triggerami;
nie dowodzimy kompletności po ich celowym wyłączeniu i spójnym przepisaniu
indeksu przez właściciela bazy. Pełny source proof obejmuje wszystkie
powiązane zdarzenia analizy, a metadata receipts — okno danego źródła.

## 9. Następny etap

Etap 10: Mini SOAR — playbooki, trwała historia run/step, retry oraz domyślna
symulacja działań infrastrukturalnych, z ochroną przed powtórzeniem skutków.
