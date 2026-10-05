# Walidacja Etapu 6 — profile encji

Data: 2026-10-05. Punkt wyjścia: `44179d9`.
Etap wdrożony do głównej aplikacji; pełna regresja i kontrole uruchomienia PASS.
Zalogowany przebieg przeglądarkowy pozostaje otwarty, zgodnie z punktem 8.
[Zakres](entities.md), [ADR 0012](adr/0012-observed-entity-profiles.md).

## 1. Zakres

Profile obserwowanych użytkowników, hostów, IP i procesów: historia aktywności,
alerty, incydenty, role, first/last seen w wybranym oknie, powiązane hosty,
zdarzenia z nieudanym logowaniem i kandydackie skojarzenia MITRE.
Ryzyko wskazuje najwyższą aktualną kwalifikującą się ocenę istniejącego alertu,
z zachowaniem jego wyjaśnienia. Starsze dane indeksuje jawny backfill administratora.

## 2. Dodane pliki

Łącznie **31 nowych plików**:

- Backend: `app/api/entities.py`; moduł `entities` z `identity`, `indexing`,
  `models`, `queries`, `schemas`, `views`, `__init__`; migracja `0010_entities.py`.
- Testy backendu: unit identity/schemas/backfill/views oraz integration
  helper_entities/test_entities/test_entities_security.
- Panel: `src/entities` — lista, profil, linki eventów, filtry, prezentacja,
  uprawnienia, typy, hook żądań i CSS; tests/entities.test.tsx i entityFixtures.ts.
- Dokumentacja: entities.md, ADR 0012 i niniejszy raport.

## 3. Zmienione pliki

Łącznie **31 istniejących plików**:

- Backend: rejestracja routera/modeli, readiness i atomowe wywołania indeksu
  w normalizerze, detectorze oraz correlatorze; README.
- Historyczne testy storage/risk/MITRE/Sigma: aktualny head 0010 oraz izolowane
  fixtures zachowujące dowód starszych blokad downgrade. Pusta warstwa 0010
  jest zdejmowana wyłącznie w testowej bazie; nie osłabiono starych blokad.
- Panel: App, Events, udostępnienie istniejącego AlertDialog w Alerts, README.
- Compose: obrazy entities-stage6; README główny i infra, dokumentacja
  architektury/API/modeli/ryzyka/bezpieczeństwa/planu, macierz i indeksy, manifest.

Zależności i lockfile bez zmian. Moduł nie dodaje usługi, portu głównej aplikacji
ani polityki obliczania ryzyka. Cały przyrost obejmuje **62 pliki**.

## 4. Endpointy

Osiem ścieżek i metod pod `/api/v1/entities`:

| Metoda | Ścieżka | Działanie |
| --- | --- | --- |
| GET | `/entities` | Lista profili |
| GET | `/entities/by-event/{event_id}` | Profile oryginalnego zdarzenia |
| GET | `/entities/{entity_id}` | Szczegóły profilu |
| GET | `/entities/{entity_id}/events` | Aktywność |
| GET | `/entities/{entity_id}/alerts` | Alerty wszystkich contributed events |
| GET | `/entities/{entity_id}/incidents` | Sprawy z aktywnych powiązań |
| GET | `/entities/{entity_id}/related` | Współobserwowane encje, domyślnie hosty |
| POST | `/entities/backfill` | Jedna audytowana partia starszych danych |

Każdy odczyt wymaga łącznie events:read, alerts:read i incidents:read;
backfill — system:manage. OpenAPI i odmowę anonimowego dostępu potwierdzono
w odizolowanym oraz głównym stosie. [Pełny kontrakt](api-contract.md).

## 5. Modele

Pięć append-only tabel: EntityIdentity, EntityObservation, EntityIndexReceipt,
EntityAlertReceipt i AlertEventReference. FK, kontrola scope/hash i kompletności
receipts, granty SELECT/INSERT oraz blokada niepustego downgrade chronią historię.
Normalized snapshot i obserwacje mają jedną transakcję; alert indeksuje wszystkie
zweryfikowane dowody, także poza kotwicą. Odczyt nie zapisuje indeksu ani ryzyka.

Polityka `entity-identity-v1` rozdziela live i dokładny replay dataset/run,
ogranicza fałszywe łączenie nazw/SID/PID oraz pokazuje podstawę identyfikacji.
`inventory_verified=false` jest jawne. Współwystępowanie nie potwierdza własności.
Zaufany runtime pozostaje granicą semantyki nowych INSERT.

Ryzyko sprawdza istniejący proof v2/v3/Sigma: policy/input hash, pochodzenie,
event IDs/SHA/czas, subject/scope i zgodność bieżącej projekcji. False positive
pozostają w historii, bez udziału w risk/MITRE; odpięte sprawy nie zwiększają
liczników, a zamknięte pozostają historią. First/last seen dotyczy wybranego okna.
Nieudane logowania liczą powiązane zdarzenia niezależnie od roli encji.

## 6. Nowe testy

Backend dodaje **186 przypadków**: 75 identity, 26 schema, 1 budżet backfillu,
28 risk views, 13 głównych integracji i 43 niezależne integracje bezpieczeństwa.
Łącznie: **1036 unit + 511 integration = 1547**, wobec wcześniejszych 1361.
Panel dodaje **35 przypadków** do 113 wcześniejszych: **148**. Skrypty: **31**.

Zakres: false joins, role i live/replay, retry/rollback, receipts bez encji,
max istniejącego risk, legacy v2 i Sigma, FP/active case links, wszystkie
contributed events, dokładne liczniki/paginacja, literalne wyszukiwanie,
podpisany cursor/principal/filtry/zasób, uprawnienia ponownie po blokadzie.
UI sprawdza spóźnione odpowiedzi po zmianie sesji/roli, filtry, replay,
backfill, MITRE/nieznane ryzyko, zamknięte sprawy i retry dowodów po 404/503.

## 7. Wyniki

| Kontrola | Wynik |
| --- | --- |
| Pełny backend, Linux/Python 3.12.14 | **1547 PASS**, 1941,11 s (32 min 21 s), bez pominięć |
| Coverage ze wspólnego przebiegu | **93%**, 7639 statements i 1908 branches |
| Jednostki lokalnie | 1036 PASS, 41,79 s |
| Panel — końcowy pełny przebieg | **148 PASS**, 21,88 s, 9 plików, bez unhandled errors |
| Skrypty na pełnym runtime poza OneDrive | **31 PASS**, 1,776 s |
| Ruff / format / MyPy / pip check w końcowym obrazie | PASS; 166 sformatowanych plików, 108 źródeł MyPy, brak konfliktów zależności |
| TypeScript / ESLint / Prettier | PASS |
| Obrazy runtime i tests | Offline build PASS, istniejące hashed locks |
| Główny launcher | Offline start z `-SkipAdmin` PASS; 93 pakiety wheelhouse z poprawnymi hashami |
| Migracje | Fresh install oraz główny upgrade 0009 → **0010_entities** PASS |
| HTTP i panel po restarcie | health/ready/OpenAPI/root/JS 200; osiem metod encji; anonimowe żądania 401; CSP self-only |
| Restart processor/detector/correlator | PASS; nowe StartedAt, Running=true, ten sam obraz co API |
| Porządek po testach | 0 baz `aegis_test_%`; stos walidacyjny zatrzymany z zachowaniem wolumenów |
| Repozytorium i dokumentacja | PASS: 375 plików tekstowych, 45 katalogów, 21 faz, 37 wymagań, 12 ADR; git diff --check PASS |

Coverage dotyczy procesu testowego, włącznie z gałęziami. Zachowanie osobnych
procesów ma dowód integracyjny, bez deklaracji ich pokrycia instrumentation.
Przebiegi naprawcze poprzedziły jeden końcowy zielony zestaw: focused 21 dał
16 PASS/5 FAIL (36,87 s), następny 71 dał 69 PASS/2 FAIL (158,78 s), a dwa
poprawione przypadki 2 PASS (4,00 s). Naprawiono walidację live dataset przy
odczycie risk i błędne oczekiwania fixtures. Pierwszy pełny UI dał 147 PASS/
1 FAIL z unhandled error przez mock timeline/notes; mock poprawiono.
Wyniki focused nie są przedstawiane jako jeden przebieg 71 PASS.

Końcowy standardowy build: 86 modułów, 751 ms; JS `index-C96NpUaw.js`
390,05 kB/gzip 110,69 kB; CSS `index-C6-tU34B.css` 19,92 kB/gzip 5,29 kB.
Alternatywny build (512 ms) ma te same assets. HTTP potwierdziło nowy JS.

Fresh `aegis-entities-20261004` na 18085 ma osobne sekrety i wolumeny.
Fresh oraz main: users, domain i wszystkie entity index counts 0.
Stan main przed upgradem: schema 0009 i te same zerowe liczniki; dane oraz
sekrety zachowano. Główna aplikacja działa na `http://localhost:8080`.
Nie tworzono kont ani fikcyjnych danych demo w głównej bazie.

Local/runtime/fresh/fulltest/main source hash:
`e45c7a527c632c81d61bcc93b6ca35fd424f8fad0b8ebc6ad193076925293f36`.
Obejmuje backend Python, migracje, katalog i licencję, z normalizacją LF;
nie obejmuje UI, testów ani zależności. Main API i trzy zrestartowane procesy
korzystają z obrazu `sha256:055b3413123acb79ff4ac610a6e4318660c803a924cfc61979006c711422a66b`.
Wyniki i logi lokalne są w ignorowanym `.local/entities`, bez sekretów w commicie.

## 8. Problemy i granice dowodu

- Zalogowany ręczny browser E2E pozostaje niezweryfikowany. Automatyczna
  kontrola odrzuciła stworzenie administratora jako zmianę uprawnień bez
  wystarczającej autoryzacji do tej konkretnej operacji. Fixture accounts
  istnieją tylko w losowych testowych bazach. Pierwsze konto w main tworzy
  użytkownik przez `Uruchom Aegis.cmd`, z ukrytym monitem hasła.
- Opcjonalny audyt podatności online nie został wykonany: kontrola odrzuciła
  transfer 48 nazw/wersji pakietów do PyPI. Osobna zgoda na ten transfer nie
  została udzielona. `pip check` i offline dry-run nie są skanem podatności.
- Start OneDrive został odrzucony również po zgodzie użytkownika ze względu
  na nieokreślony zakres danych i konto docelowe. Użyto Dockera i kompletnego
  runtime poza OneDrive. Hostowane CI nadal nie ma zweryfikowanego przebiegu.
- Docker po przerwie był wyłączony, a zwykły start ponownie odtworzył błąd
  AF_UNIX `dockerInference`. Zachowano kopie dwóch zweryfikowanych katalogów
  komunikacji, zatrzymano tylko procesy z instalacji Docker i wznowiono
  oficjalny Desktop. Engine 29.7.2 oraz główny stos odzyskano; nie usuwano
  wolumenów ani danych. Przyczyna nawrotów pozostaje nieustalona. Końcowe
  HTTP/stan/restart sprawdzono po ostatnim odzyskaniu silnika.
- Historia aktywności profilu korzysta z PostgreSQL. Pełne zdarzenie otwiera
  dotychczasowe ClickHouse API; brak projekcji/awaria daje jawne 404/503 i retry.
  Dowody alertu pozostają w PostgreSQL.
- Tożsamości są twierdzeniami źródła, bez weryfikacji CMDB. Każda odpowiedź
  ma spójny snapshot SQL; cursor filtruje zapisane timestampy, lecz nie
  zachowuje wspólnego snapshotu bazy między stronami. Późniejszy commit ze
  wcześniejszym timestampem, nowe decyzje FP, risk i case links mogą zmienić
  kolejne odpowiedzi. Backfill status obejmuje znane normalized events/alerty,
  a backlog raw pipeline pozostaje osobnym stanem.

## 9. Kolejny etap

**Etap 7 — lokalne Threat Intelligence i IOC**: IP/domain/URL/hash,
normalizacja, uprawnienia, wersjonowane pochodzenie i dowód dopasowania.
Interfejs providerów ma umożliwić dalszą rozbudowę; lokalny MVP nie potrzebuje
zewnętrznych kluczy ani automatycznego otwierania URL z logów.
