# Plan implementacji Aegis SOC Command Center

## Zakres i stan planu

Aktualizacja 2026-10-01: nowa prośba użytkownika wyznacza 15 przyrostów,
zaczynając od incydentów. [Audyt i plan rozbudowy](soc-expansion-plan.md)
określa bieżącą kolejność; poniższe PHASE 0–20 zachowują historyczny plan
i kryteria jakości. Każdy nowy przyrost pozostawia aplikację uruchamialną.
Etap 1 dostarczył [incydenty](validation-incidents.md); Etap 2 dostarcza
[korelację liczników i sekwencji](validation-correlation.md).
Nie obejmuje przyszłego merge/grafu/reconstruct z historycznej PHASE 6.

Plan odpowiada fazom 0–20 wskazanym w wymaganiach. Faza 0 dostarczyła analizę stanu, decyzje architektoniczne, szkielet repozytorium i dokumentację. Faza 1 dostarczyła zweryfikowany fundament backendu z integracją rzeczywistych usług (2026-09-28). SIEM, frontend i generator wymagają dalszych faz.

Punktem wyjścia jest puste repozytorium opisane w [raporcie stanu](current-state-report.md). Docelową architekturę i odpowiedzialności komponentów opisuje [architecture.md](architecture.md), a układ plików [repository-structure.md](repository-structure.md). Pełne pokrycie wymagań użytkownika zawiera [macierz wymagań](requirements-traceability.md).

**Stan przyrostu:** fazy 0–3 są ukończone. PHASE 3: 643 passed, coverage 91%;
commit `f0d2ff3`. Początkowe trzy detekcje pojedynczego zdarzenia i panel
obsługujący ten zakres są osobnym, częściowym przyrostem faz 4/5/13
na prośbę o działanie całej aplikacji z folderu. Nie zamykają pełnych faz 4–13.
[Zakres](initial-soc.md), [aktualna walidacja](validation-initial-soc.md).

Historycznie: fazy 0–2 są ukończone. PHASE 2 zweryfikowano 2026-09-30: wspólny przebieg 341 testów jednostkowych i 113 integracyjnych dał **454 passed**, z coverage 91% procesu testowego. Potwierdzono trwałość, role, limity, migracje, realny przepływ HTTP → relay → prefork worker oraz wznowienie po zatrzymaniu workera. W tamtym raporcie fazy 3–20 były zaplanowane; aktualny stan opisano powyżej. Wyniki, odstępstwo lokalnego build oraz Conventional Commit zapisuje [raport walidacji](validation.md). Historyczny dowód fundamentu pozostaje w [raporcie PHASE 1](validation-phase1.md). Brak zdalnego repozytorium i przebiegu GitHub Actions oznacza niezweryfikowane hostowane CI. Końcowe kryteria Definition of Done całej platformy pozostają otwarte.

## Ustalenia wspólne

- Backend jest modularnym monolitem FastAPI/Pydantic/SQLAlchemy na Python 3.12.14; lokalne środowisko, kontener i CI używają tej samej wersji. Uzasadnienie aktualizacji wcześniejszego planu 3.13 zapisano w [ADR 0001](adr/0001-modular-monolith.md). Planowany frontend React/TypeScript/Vite korzysta z rzeczywistego API.
- PostgreSQL przechowuje stan biznesowy, użytkowników, reguły, zdarzenia audytowe oraz trwałe inbox/outbox, postęp przetwarzania i kopie dowodów. ClickHouse służy do analityki i archiwum eventów. Redis jest transportem Celery, cache i mechanizmem ograniczania ruchu; nie jest jedynym miejscem zapisu stanu detekcji.
- Worker przetwarza co najmniej raz. Idempotencja etapów, klucze deduplikacji i możliwość odtworzenia pracy są wymaganiami od pierwszego pionowego przyrostu.
- MVP działa lokalnie dla jednej organizacji. Role ograniczają czynności; nie deklarujemy izolacji wielu klientów ani gotowości do publicznego Internetu bez dodatkowego przeglądu.
- Wszystkie akcje SOAR wpływające na infrastrukturę pozostają symulacją. Demo emituje logi do publicznego kontraktu ingestion; nie zapisuje gotowych alertów ani incydentów do baz.
- Migracje PostgreSQL wykonuje Alembic. Zmiany ClickHouse mają osobne, wersjonowane migracje. `create_all()` nie zastępuje wdrożeniowych migracji.
- Bezpieczeństwo, testy, logowanie i dokumentacja powstają razem z modułami od fazy 1. Fazy 15–19 rozszerzają, scalają i weryfikują istniejące mechanizmy.
- Przed pierwszym kodem integracji należy sprawdzić aktualne oficjalne dokumentacje, wybrać zgodne wersje zależności, zablokować je w lockfile i obrazach oraz zapisać uzasadnienie istotnych zmian w ADR. Plan nie obiecuje konkretnych, jeszcze niezweryfikowanych wersji.

## Bramka zamknięcia każdej fazy

1. Uruchom testy właściwe dla zmienionego kodu i zachowaj wynik oraz dokładne komendy.
2. Uruchom lint, kontrolę formatowania i typów odpowiednie do istniejących języków. W fazie 0 stosuj walidator szkieletu i kontrolę dokumentów; nie opisuj tego jako testów aplikacji.
3. Sprawdź integrację bieżącego przyrostu z poprzednimi: od fazy 1 z rzeczywistymi usługami, od fazy 13 także przez przeglądarkę. Każdy moduł ukończony przed fazą 13 musi mieć działające API, trwały zapis i test integracyjny; integracja UI jest osobną, jawną bramką fazy 13.
4. Napraw nowe błędy. Wcześniejsze błędy opisz wraz z wpływem; uszkodzona zależność blokuje następną fazę.
5. Zaktualizuj kontrakty, instrukcję uruchomienia, ADR i macierz wymagań. Zapisz pozostałe ograniczenia.
6. Wykonaj spójny Conventional Commit (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:` albo `ci:`). Bez force push. Nie traktuj samego commita jako dowodu poprawności.

Rejestr wykonania powinien zawierać fazę, zakres, datę, środowisko, komendy, wyniki, odstępstwa oraz identyfikator commita. Wynik nieuruchomionego testu to **niezweryfikowany**, a nie zielony. Wymagane kontrole PR należy skonfigurować w hostowanym repozytorium, kiedy będzie dostępne.

## Zależności i kamienie milowe

Pełne fazy zachowują kolejność `0 → 1 → 2 → … → 20`. Wczesny panel obsługuje
wyłącznie istniejące API po zweryfikowaniu fazy 3 i nie zastępuje bramek
przyszłych modułów. Jawny wyjątek zakresu: ADR 0004 i ADR 0005. Poniższe zależności wskazują konkretne kontrakty potrzebne kolejnym fazom, a nie pozwolenie na pomijanie bramek.

| Kamień milowy | Fazy | Wymagany dowód |
| --- | --- | --- |
| Projekt i fundament | 0–1 | Zweryfikowany szkielet, uruchomione API, migracje, logowanie i test odmowy RBAC |
| Działająca detekcja | 2–5 | Surowe logi przez ingestion i normalizację do objaśnionego alertu, również po ponownym dostarczeniu |
| Kontekst incydentu | 6–10 | Korelacja, incydent, storyline, MITRE, deterministyczny risk score i lokalne IOC |
| Praca analityka | 11–13 | Hunting, symulowane playbooki i UI operujące na rzeczywistym API |
| Powtarzalne demo | 14–15 | Siedem scenariuszy przez pełny pipeline oraz widoczne opóźnienia i awarie |
| Gotowość do prezentacji | 16–20 | Przegląd bezpieczeństwa, regresja, kompletna dokumentacja, potwierdzone CI i końcowa próba demo |

## PHASE 0 — Architecture / ADR / repository structure

**Zależności:** raport z odczytu rzeczywistego katalogu roboczego; brak założeń o istniejącym kodzie.

**Zadania:**

- Zarejestrować zawartość, stan Git, dostępne narzędzia i ograniczenia środowiska w `docs/current-state-report.md`.
- Opisać granice modułów, przepływ danych, trwałość, model błędów, bezpieczeństwo i trade-offy w `docs/architecture.md` oraz ADR.
- Utworzyć szkielet `backend`, `frontend`, `detection-content`, `demo`, `infra`, `scripts`, `docs`, katalogów testów i workflow fazy 0; opisać planowane komponenty bez pozorowania ich działania.
- Zdefiniować wspólny kontrakt zdarzeń, odpowiedzialność magazynów, politykę symulacji SOAR i plan wszystkich faz wraz z macierzą wymagań.
- Dodać walidator struktury i dokumentów oraz bootstrap CI uruchamiający wyłącznie dostępne kontrole fazy 0.

**Artefakty:** raport, architektura i diagram Mermaid, ADR, dokumentacja struktury, niniejszy plan, macierz wymagań, README, `scripts/validate_repository.py`, `.github/workflows/phase0.yml`.

**Weryfikacja:** `py scripts/validate_repository.py` lokalnie lub `python scripts/validate_repository.py` w CI; sprawdzenie składni Pythona przez AST, kontrola diff, ścieżek i zgodności dokumentów. Walidator jest kontrolą dokumentacji i struktury. Integracja na tym etapie oznacza zgodność dokumentacji, szkieletu i workflow. Testy API, baz i kontenerów nie mają jeszcze implementacji.

**Ukończenie:** opisano obecny i docelowy stan, każde wymaganie ma właściciela w planie, szkielet przechodzi lokalne kontrole, nie nadpisano istniejących funkcjonalności i zapisano Conventional Commit. Nie oznacza to ukończenia całego projektu ani zielonego hostowanego CI.

## PHASE 1 — Backend foundation

**Zależności:** 0; zatwierdzone granice modułów i model trwałości.

**Stan: COMPLETE — ukończona i zweryfikowana 2026-09-28.** Pliki wykonawcze obejmują
`backend/app`, migrację `backend/migrations/versions/0001_foundation.py`, lockfile
z hashami, `backend/Dockerfile`, `compose.yaml` i `.github/workflows/backend.yml`.
Testy jednostkowe: **230 passed in 16.40s**, coverage 65%. Osobny przebieg integracyjny
z PostgreSQL/Redis/ClickHouse/Celery: **33 passed, 230 deselected in 32.30s**, coverage
82%. Są to dwa odrębne pomiary coverage; nie wyznaczają łącznego pokrycia.
Przeszły build obrazów Linux/Python 3.12.14, `docker compose up -d --wait` na świeżym
stosie, migrator (exit 0), sondy przez proxy i zadanie Celery. Test współbieżnego
refresh i zmiany konta wykrył kontrolowane przywrócenie błędnego `FOR UPDATE`
(odpowiedź 503), a poprawiona blokada przeszła integrację. Instalacja dev lockfile
z `--require-hashes`, `pip check` i audyt runtime lock przeszły.
Uruchomienie i kryteria operacyjne opisuje
[instrukcja PHASE 1](phase1-operations.md); dokładne wyniki zapisuje
[raport walidacji](validation.md). Hostowane CI pozostaje niezweryfikowane.
Wyniki historyczne PHASE 1 zachowuje [raport PHASE 1](validation-phase1.md).

**Zadania:**

- Utworzyć aplikację FastAPI, konfigurację walidowaną przy starcie, wersjonowane `/api/v1`, kontrakt błędów, dependency injection i moduły domenowe.
- Dodać PostgreSQL/SQLAlchemy/Alembic, inicjalne migracje użytkowników, sesji i audytu, gotowość ClickHouse, Redis i Celery oraz minimalny Docker Compose do prac lokalnych.
- Wdrożyć hashowanie haseł, krótkie access JWT, rotowane refresh tokens z zapisem skrótów, unieważnianie sesji i bezpieczną inicjalizację administratora bez stałego hasła.
- Wdrożyć role Admin, SOC Manager, SOC Analyst i Read Only z macierzą permissions; dodać `/auth`, `/users`, `/audit`, audit log append-only dla zwykłych użytkowników, limitowanie logowania i bezpieczne błędy.
- Dodać `/health`, `/ready`, podstawowe `/metrics`, logi JSON z request ID, Ruff, format check, kontrolę typów i minimalne CI aplikacyjne.

**Artefakty:** działający backend, migracje, pliki zależności z blokadą wersji, Compose lokalny, konfiguracja testów i dokumentowany model bezpieczeństwa.

**Weryfikacja:** testy jednostkowe konfiguracji i permissions; API login/refresh/logout, ponownego użycia refresh tokenu, błędnego JWT i odmowy dostępu; integracja migracji na pustym PostgreSQL, worker smoke i awarii zależności w `/ready`; lint/format/type check. Hasła i tokeny nie mogą trafić do logów.

**Ukończenie:** lokalny start według instrukcji, migracje zamiast `create_all`, działające uwierzytelnienie, kontrola ról po stronie serwera i audyt operacji. Kolejne API korzystają z tych mechanizmów od początku.

## PHASE 2 — Event ingestion

**Stan: COMPLETE — ukończona i zweryfikowana 2026-09-30.** Zakres: migracja `0002_ingestion`,
API źródeł i credentiali, atomowe single/batch, deduplikacja, inbox/outbox, relay,
worker, status operatora i ręczne retry. Raw staging jest odrębne od normalizacji.
Kontrakt i procedury: [obsługa PHASE 2](phase2-operations.md).
Wspólna regresja: **454 passed in 106.81s**, coverage 91% procesu testowego.
Testy osobnych procesów potwierdzają HTTP → relay → prefork → `staged` i restart
workera; 30 dodatkowych prób współbieżnego admission przeszło po poprawce
inicjalizacji schematów API. Szczegóły i ograniczenia: [walidacja](validation.md).

**Zależności:** 1; uwierzytelniony kontrakt API, PostgreSQL i worker.

**Zadania:**

- Wprowadzić `RawEvent`, `/api/v1/events` dla pojedynczego zdarzenia i batch oraz uwierzytelnienie źródeł ingestion o uprawnieniach oddzielonych od pracy analityka.
- Określić limity rozmiaru, liczby rekordów i przepustowości, schemat odpowiedzi batch, obsługę błędów częściowych, identyfikatory źródła i klucze idempotencji.
- Zapisywać zaakceptowany event wraz z zadaniem w trwałym inbox/outbox w jednej transakcji PostgreSQL. Potwierdzenie przyjęcia nie oznacza zakończonej analizy.
- Dodać dispatcher, retry z ograniczeniem, stan przetwarzania, kwarantannę błędów i kontrolowane ponowienie. Zdefiniować mierzalny backpressure, gdy zależności nie nadążają.

**Artefakty:** moduł ingestion, migracje inbox/outbox, endpoint statusu ingestii, fixture surowych formatów, kontrakt batch i instrukcja replay.

**Weryfikacja:** API pustego i uszkodzonego batch, przekroczenia limitów, uprawnień i powtórzonego klucza; integracja awarii po commicie przed enqueue, ponownego dostarczenia zadania, niedostępności Redis i restartu workera; lint i typy.

**Ukończenie:** potwierdzone logi nie giną po restarcie transportu, retry nie mnoży logicznych eventów, status jest widoczny, a zły rekord nie blokuje bezterminowo zdrowych danych. Parsowanie i generowanie alertów pozostają następnymi fazami.

## PHASE 3 — Normalization

**Zależności:** 2; trwały `RawEvent` i idempotentne zadania.

**Zadania:**

- Zaimplementować wersjonowany `NormalizedSecurityEvent` inspirowany ECS i OpenTelemetry, ze źródłowym i obserwowanym czasem, raw event, polami użytkownika, hosta, procesu, sieci, akcji i wyniku.
- Dodać rejestr parserów Linux auth/SSH/sudo, Windows authentication/process, firewall, nginx i generic JSON; udokumentować obsługiwane warianty i brakujące dane.
- Rozstrzygnąć strefy czasowe, błędne IP/porty, eventy spóźnione i kolejność przetwarzania; zachować pochodzenie i wersję parsera.
- Zapisywać analityczne eventy do ClickHouse z wersjonowanym schematem i jawną strategią deduplikacji odczytu; trwałe potwierdzenia etapów pozostawić w PostgreSQL.
- Dostarczyć ograniczony query builder/AST, allowlistę pól i parametryzowane zapytania event search: czas, użytkownik, IP, host, process, severity, typ i źródło. Filtry MITRE i reguły uzupełnią fazy 4/8.

**Artefakty:** parsery, kontrakt zdarzeń, migracje ClickHouse, event search API, golden fixtures oraz dokumentacja normalizacji, czasu i retencji.

**Weryfikacja:** testy wszystkich parserów na poprawnych i uszkodzonych wejściach, Unicode i brakujących polach; testy injection/limitów AST; integracja raw → normalized → wyszukiwanie w prawdziwym ClickHouse i retry po zapisie; lint/typy.

**Ukończenie:** każde wymagane źródło ma fixture i działający parser; wyniki wyszukiwania po replay nie zawyżają liczności. Nieznany format otrzymuje jawny błąd lub kwarantannę, bez cichego odrzucenia.

## PHASE 4 — Detection Engine

**Zależności:** 3; stabilny schemat, event time i mechanizm trwałego postępu.

**Zadania:**

- Dodać wewnętrzny model reguł, wersjonowane definicje i `/detections`: CRUD, enabled, severity/confidence, MITRE, author, references i false positive guidance.
- Zaimplementować single-event, threshold, time-window, sequence oraz deklaratywne correlation detections. Korelacja warunków reguły jest odrębna od grupowania alertów w fazie 6.
- Ustalić klucze grupowania, granice okien, dopuszczalne spóźnienie, deduplikację wyników i przechowywany w PostgreSQL stan okien/realizacji. Restart Redis nie zeruje historii detekcji.
- Importować i walidować udokumentowany subset Sigma YAML, ograniczyć parser YAML i odrzucać nieobsługiwane konstrukcje zamiast zmieniać ich znaczenie.
- Dodać reguły brute force, udane logowanie po nieudanych próbach, suspicious PowerShell, privilege escalation i utworzenie administratora oraz endpoint rule-test uruchamiany bez skutków w produkcyjnym stanie.

**Artefakty:** silnik, repozytorium reguł, specyfikacja Sigma subset, zestawy given events/expected detections i `docs/detection-engine.md`.

**Weryfikacja:** przypadki 9/10 prób i granic 5 minut, sukces przed/po serii, sekwencje poza kolejnością, restart, retry, wyłączenie i zmiana wersji reguły; testy negatywne/false positives i regression fixtures; integracja ingestion → wynik reguły; lint/typy.

**Ukończenie:** każdy tryb reguły działa na rzeczywistych danych i ma testy pozytywne oraz negatywne; wynik wskazuje wersję reguły i identyfikatory eventów. Test reguły nie emituje rzeczywistych alertów ani zadań SOAR.

## PHASE 5 — Alert Management

**Zależności:** 4; trwałe, idempotentne wyniki detekcji.

**Zadania:**

- Zapisywać alerty w PostgreSQL i udostępnić listę, szczegół, filtrowanie i stronicowanie przez `/alerts`.
- Zachować snapshot reguły, wkład eventów i dowody potrzebne także po retencji archiwum; zdefiniować stabilny klucz alertu dla replay.
- Dodać explainability: co, dlaczego, kiedy, gdzie, kto, reguła, eventy i przypisany MITRE; zaplanować pola wkładu ryzyka, których wartości wypełni faza 9.
- Rejestrować potwierdzenie przyjęcia do obsługi i zmiany analityka wraz z aktorem i timestamp; zapewnić autoryzację oraz audit trail.

**Artefakty:** migracje i moduł alertów, API oraz kontrakt szczegółu alertu.

**Weryfikacja:** trwałość po restarcie, równoległe dostarczenie tej samej detekcji, paginacja, RBAC, aktualizacja reguły po wygenerowaniu alertu i dostęp do snapshotu dowodów; pełny test ingestion → alert; lint/typy.

**Ukończenie:** alert jest wytworzony przez detekcję, ma wyjaśnienie i dowody, a replay nie tworzy kopii. Niewyliczony risk score pozostaje jawnie nieobliczony; nie jest pozorną wartością 0.

## PHASE 6 — Correlation Engine

**Zależności:** 5; trwałe alerty i indeksowane encje użytkownika, hosta, IP.

**Zadania:**

- Zaprojektować deterministyczne zasady łączenia alertów według user/host/IP/czasu, reguł i kontekstu MITRE, z wyjaśnieniem każdej krawędzi.
- Unikać przypadkowego łączenia wszystkich zdarzeń ze wspólnego NAT; wprowadzić wymagane kotwice encji i jawne ograniczenia czasu/rozmiaru grupy.
- Zapisywać grupy korelacji, członkostwo, wersję polityki i decyzje; zapewnić blokady lub bezpieczne transakcje równoległych aktualizacji.
- Przygotować kontrakt idempotentnego tworzenia/aktualizacji incydentu przez fazę 7 oraz reguły późnego dołączenia i ponownego otwarcia/grupowania.

**Artefakty:** moduł korelacji, migracje, fixture attack chain i `docs/correlation-engine.md`.

**Weryfikacja:** dodatni attack chain, różni użytkownicy za NAT, podobne techniki na niezależnych hostach, przerwa poza oknem, zdarzenia spóźnione, równoległe zadania i replay; integracja alerts → correlation groups; lint/typy.

**Ukończenie:** powiązane alerty dają jedną stabilną grupę; niepowiązane pozostają oddzielone. Każde powiązanie ma dowód i uzasadnienie.

## PHASE 7 — Incident Management

**Zależności:** 6; stabilne grupy alertów i API audytu z fazy 1.

**Zadania:**

- Dodać `/incidents`, idempotentne tworzenie z grupy korelacji, powiązania event/alert/IOC, owner, notatki, komentarze i evidence.
- Wdrożyć stany New, Triaged, Investigating, Contained, Resolved, False Positive z macierzą dozwolonych przejść, kontrolą współbieżnych zmian i wymaganymi timestampami.
- Zbudować storyline jako deterministyczną chronologiczną projekcję dowodów z rozróżnieniem czasu zdarzenia i działań analityka; nie generować faktów bez dowodu.
- Obsłużyć dowody jako niezmienne snapshoty i kontrolowane załączniki z limitami, skrótem integralności i bezpiecznym pobieraniem; audytować każdą mutację case management.

**Artefakty:** model incydentu i investigation, API współpracy analityka, migracje, `docs/incident-response.md`.

**Weryfikacja:** przejścia i odrzucane przejścia stanów, podwójne tworzenie z grupy, równoległa edycja, permissions, kompletność audytu, niebezpieczny załącznik i zgodność timeline ze źródłem; integracja ingestion → incident; lint/typy.

**Ukończenie:** analityk może przeprowadzić case od utworzenia do zamknięcia lub false positive, a historia odtwarza kto, co i kiedy zmienił. Attack chain jest oparty na rzeczywistych powiązaniach; nazwy MITRE i ocena ryzyka będą wzbogacone w fazach 8–9.

## PHASE 8 — MITRE ATT&CK

**Zależności:** 4, 6, 7; metadane technik przewidziane w kontraktach od fazy 4.

**Zadania:**

- Dodać wersjonowany, lokalnie dostępny katalog używanego zakresu ATT&CK z pochodzeniem, wersją i informacją o licencji/atrybucji.
- Walidować tactic, technique i sub-technique w regułach, zachowywać wersję mapowania w snapshotach alertów i incydentów.
- Udostępnić faktyczny łańcuch technik w timeline oraz filtry wyszukiwania po technique i detection rule z kontrolą powiązań między PostgreSQL i ClickHouse.

**Artefakty:** katalog MITRE, walidacja, API chain/distribution oraz uaktualnione reguły i dokumentacja.

**Weryfikacja:** nieznany identyfikator, relacja sub-technique, brak mapowania, zmiana wersji katalogu i deterministyczna kolejność chain; integracja reguła → alert → incydent → filtr eventów; lint/typy.

**Ukończenie:** mapowania są sprawdzalne i dostępne offline, a storyline pokazuje tylko techniki wynikające z dowodów. Samo mapowanie ATT&CK nie stanowi dowodu skutecznego ataku.

## PHASE 9 — Risk Engine

**Zależności:** 7–8; powiązane alerty i kontekst incydentu. IOC jest zdefiniowanym interfejsem, dane dostarczy faza 10.

**Zadania:**

- Zdefiniować i udokumentować wersjonowany algorytm 0–100 dla alertu i incydentu z severity, confidence, criticality, IOC, liczbą alertów, MITRE, previous activity i privileges.
- Ustalić źródła danych wejściowych, ograniczone wkłady czynników, normalizację, reguły braku danych i ochronę przed wielokrotnym naliczaniem powtórzonego dowodu.
- Zapisywać snapshot wejść, wersję algorytmu i rozbicie wyniku. Przeliczenie po wzbogaceniu tworzy nową wersję oceny, zachowując poprzednią.
- Dodać zarządzanie podstawowym kontekstem hostów/kont z RBAC; brak danych IOC do fazy 10 jest jawnie oznaczony, a nie fikcyjną dobrą reputacją.

**Artefakty:** moduł scoringu, migracje, API wyjaśnienia, fixture ocen i `docs/risk-engine.md`.

**Weryfikacja:** deterministyczność, granice 0/100, brak danych, monotoniczność zatwierdzonych czynników, deduplikacja, zgodność sumy wkładów i odtworzenie starej oceny; integracja alert/incident → score; lint/typy.

**Ukończenie:** każdy oceniony alert/incydent ujawnia źródła i wkłady wyniku; ten sam snapshot i wersja algorytmu zawsze zwracają ten sam wynik. Ocena nie zależy od niejawnego stanu zewnętrznej usługi.

## PHASE 10 — Threat Intelligence

**Zależności:** 3, 4, 9; schemat encji i kontrakt wzbogacania/scoringu.

**Zadania:**

- Utworzyć lokalną bazę i `/iocs` dla IP, domain, URL i hash, z source, confidence, severity, tags, first/last seen i description.
- Wdrożyć jawne, bezpieczne reguły kanonikalizacji i dopasowania: m.in. normalizacja hosta domeny bez automatycznego traktowania każdego prefiksu URL jako IOC.
- Dopasowywać rzeczywiste eventy do wersjonowanego snapshotu IOC, tworzyć wyjaśniony wynik detekcji i wzbogacać ocenę ryzyka z audytem zmiany.
- Zdefiniować interfejs dostawców VirusTotal/AbuseIPDB/OTX na przyszłość bez wymagania kluczy i bez ukrytych wywołań zewnętrznych w MVP.

**Artefakty:** model IOC, migracje, API importu/CRUD, lokalne dane demo i dokumentacja pochodzenia/dopasowania.

**Weryfikacja:** wszystkie typy IOC, nieprawidłowe wartości, wielkość liter domen, IPv6, dokładność hash, false positives URL, retry dopasowania i zmiana reputacji; integracja ingestion → IOC match → alert/risk; lint/typy.

**Ukończenie:** pipeline wykrywa lokalny IOC i pokazuje źródło dopasowania oraz wpływ na ryzyko; działa bez zewnętrznych usług.

## PHASE 11 — Threat Hunting

**Zależności:** 3–5, 7–10; event search, zarządzanie regułami i investigation.

**Zadania:**

- Udostępnić `/hunts` z zapisem zapytań, właścicielem, opisem hipotezy, wersją query AST i bookmarkami eventów.
- Obsłużyć uruchomienie ograniczonego zapytania na ClickHouse, zapis wyników/dowodów oraz utworzenie investigation z wybranych eventów.
- Umożliwić utworzenie szkicu detekcji z zachowania, walidację i test fixture przed włączeniem reguły; uprawnienia do hunt i publikacji reguły pozostają odrębne.
- Dodać przykładowe hunting queries: logowania po serii błędów, nietypowy PowerShell, nowi administratorzy i aktywność IOC.

**Artefakty:** API hunts, zapytania przykładowe, migracje i `docs/threat-hunting.md`.

**Weryfikacja:** zapis/odtworzenie query AST, limity czasu i liczby wyników, injection, wygasły event z zachowanym dowodem, RBAC szkicu/publikacji i hunt → investigation → rule-test; lint/typy.

**Ukończenie:** analityk może przejść od hipotezy do dowodów, investigation i testowanego szkicu reguły przez API; brak automatycznego aktywowania niesprawdzonej detekcji.

## PHASE 12 — SOAR

**Zależności:** 7, 9, 10; incident, scoring, IOC i trwały model pracy z fazy 2.

**Zadania:**

- Dodać `/playbooks`, wersjonowane definicje kroków, walidację parametrów i allowlistę handlerów; bez wykonywania dowolnego kodu z definicji.
- Zapisywać run/step/input/output/history w PostgreSQL. Każdy krok ma waiting, running, completed lub failed; określić timeout, retry i recovery przerwanego running.
- Zaimplementować enrich_ip, check_threat_intelligence, calculate_risk, idempotentne create_incident i notify_analyst jako powiadomienie wewnątrz aplikacji.
- Oznaczyć tryb symulacji w API i wynikach. Blokowanie IP, izolacja hosta i podobne działania mogą wyłącznie tworzyć wynik symulacji; konfiguracja nie może włączyć prawdziwej operacji infrastrukturalnej.

**Artefakty:** silnik i rejestr akcji, migracje wykonań, przykładowy Brute Force Response, `docs/soar.md`.

**Weryfikacja:** prawidłowe przejścia kroków, błąd/timeout, restart workera w połowie kroku, retry bez powtórnego incydentu, niedozwolona akcja, RBAC uruchomienia i audyt; integracja incident → playbook → persisted run; lint/typy.

**Ukończenie:** cały playbook przechodzi przez rzeczywisty worker i trwałą historię, a działania infrastrukturalne pozostają wyłącznie symulowane. Nie ma niejawnego wysyłania e-maili ani komunikatów do zewnętrznych odbiorców.

## PHASE 13 — Frontend

**Zależności:** 1–12; stabilne kontrakty API i dostępne dane testowe z fixture.

**Zadania:**

- Utworzyć React/TypeScript/Vite, typowanego klienta API, bezpieczny przepływ sesji i widoki zgodne z uprawnieniami; serwer nadal egzekwuje RBAC.
- Zbudować dark mode i czytelny układ: Overview, Alerts, Incidents, Investigation, Threat Hunting, Detection Rules, Threat Intelligence, SOAR Playbooks, Event Explorer, System Health, Audit Log.
- Dodać filtry, paginację, stany loading/empty/error, timeline/storyline, risk breakdown, evidence, rule-test i wykonania SOAR z jawnym oznaczeniem symulacji.
- Zapewnić nawigację Alert → Events → User → Host → IOC → Incident; User/Host otwierają kontekst i filtrowane dane, bez wymyślania telemetrii endpointów.
- Zintegrować dashboard z agregacjami API: alerts/24h, incidents/critical, EPS, top rules/IP/accounts, severity i MITRE. Metryki SOC z fazy 15 mają jawne definicje i uzupełnią widok.

**Artefakty:** działający frontend, klient OpenAPI, komponenty i testy przeglądarkowe, aktualizacja Compose.

**Weryfikacja:** lint, format, `tsc`, build, testy komponentów kluczowych formularzy; E2E login, odmowa roli, wyszukiwanie, triage incydentu, rule-test i symulowany playbook na prawdziwym API; sprawdzenie klawiatury, kontrastu, błędów i pustych danych.

**Ukończenie:** każdy główny widok odczytuje lub zapisuje realne dane, a podstawowe zadania analityka da się wykonać bez ręcznych wywołań API. Produkcyjne widoki nie używają tablic mock zamiast backendu.

## PHASE 14 — Demo scenarios

**Zależności:** 1–13; pełny pipeline i działające UI.

**Zadania:**

- Dodać seedowaną generację normalnej aktywności oraz scenariuszy: SSH brute force; brute force → success; suspicious PowerShell; privilege escalation; malicious IP IOC; account compromise chain; new administrator account.
- Wysyłać logi przez `/api/v1/events` z identyfikatorem uruchomienia i kontrolowanym zegarem/czasem scenariusza. Reguły, użytkownicy i IOC mogą być bootstrapem konfiguracji; alerty i incydenty muszą powstać przez pipeline.
- Zapisać manifest oczekiwanych reguł, grup, incydentów, technik i zakresów/wyjaśnień ryzyka. Dodać instrukcję czystego startu, bezpiecznego resetu danych demo i ponownego uruchomienia.
- Przygotować scenariusz prezentacji 30–60 minut, pozwalający wyjaśnić poprawne wyniki i ograniczenia.

**Artefakty:** generator `demo`, fixture i manifesty siedmiu scenariuszy, komendy demo oraz dane bez rzeczywistych sekretów i danych osobowych.

**Weryfikacja:** pełny E2E każdego scenariusza, pozytywna i negatywna aktywność, identyczny seed, replay tej samej emisji oraz nowy run; weryfikacja idempotencji bez bezpośrednich zapisów alertów/incydentów; lint/typy.

**Ukończenie:** siedem scenariuszy daje oczekiwane skutki widoczne w UI, a typowy benign baseline ma określone, sprawdzone oczekiwania. Demo działa bez zewnętrznych usług po dostępności wymaganych obrazów/zależności.

## PHASE 15 — Observability

**Zależności:** 1–14; metryki i request ID istnieją od fundamentu.

**Zadania:**

- Ujednolicić structured logs i identyfikatory na ścieżce API → outbox → worker → alert/incident/playbook; nie logować sekretów ani całych wrażliwych payloadów.
- Rozszerzyć `/health`, `/ready`, chronione `/metrics` o processed events, generated alerts, latency, failed events, backlog, retry i playbook executions; ograniczyć cardinality etykiet.
- Dodać `/api/v1/metrics` dla agregatów SOC oraz definicje MTTD, MTTA, MTTR, false positive rate, alerts/incidents per day i noisy rules.
- Jawnie zdefiniować początkowe/końcowe timestampy, kohorty, mianowniki, reopen i brakujące wartości. Nie mieszać opóźnienia przetwarzania z MTTD ani nie podawać 0 dla braku próbek.
- Zintegrować dashboard i System Health z rzeczywistymi licznikami i runbookiem awarii.

**Artefakty:** metryki techniczne i biznesowe, kontrakt agregatów, dokumentacja obserwowalności i runbook.

**Weryfikacja:** znany zbiór timestampów z ręcznie policzonym wynikiem, pusta kohorta, reopen, brak acknowledgment; test awarii PostgreSQL/ClickHouse/Redis i narastania backlogu; zgodność liczników z przetwarzaniem; lint/typy.

**Ukończenie:** operator rozpoznaje opóźnienie, kwarantannę i niedostępność komponentu, a metryki SOC mają odtwarzalną definicję i rzeczywiste dane.

## PHASE 16 — Security hardening

**Zależności:** 1–15; przegląd istniejących zabezpieczeń, nie ich pierwsza implementacja.

**Zadania:**

- Zweryfikować threat model, granice zaufania i całą macierz RBAC w endpointach, workerach, eksporcie danych i UI.
- Sprawdzić token lifecycle, ciasteczka/CORS/CSRF, nagłówki, hashing, rate limiting, źródła ingestion, redakcję logów i błędy; wymusić bezpieczne konfiguracje.
- Przetestować SQL/query/YAML injection, XSS w raw event/notatkach, path traversal w evidence, niebezpieczne uploady, DoS przez batch/query/reguły oraz wywołania URL bez niezamierzonego SSRF.
- Utwardzić kontenery, uprawnienia baz, ekspozycję portów i sekrety z otoczenia; sprawdzić zależności i obrazy oraz usunąć wykryte podatności lub udokumentować ograniczenia z uzasadnieniem.
- Zweryfikować brak infrastrukturalnych efektów SOAR i odporność audytu na modyfikację przez zwykłego użytkownika; udokumentować ograniczenie względem administratora bazy.

**Artefakty:** zaktualizowane `docs/security.md`, wyniki przeglądu, poprawki i testy regresyjne wykrytych problemów.

**Weryfikacja:** negatywne testy API dla każdej roli i obiektu, testy sesji i wejść wrogich, secret/dependency scanning, integracja konfiguracji Compose; lint/typy i istniejąca regresja.

**Ukończenie:** brak otwartych krytycznych błędów bezpieczeństwa w zadeklarowanym lokalnym modelu; ograniczenia oraz wymagania przyszłego deploymentu są jawne. Nie deklarujemy certyfikacji ani pentestu wykonanego przez zewnętrzny zespół.

## PHASE 17 — Testing

**Zależności:** 1–16; konsolidacja testów rozwijanych przez cały projekt.

**Zadania:**

- Uzupełnić luki w unit/integration/API/detection/correlation/risk/RBAC/E2E na podstawie ryzyka i macierzy wymagań.
- Ustalić blokujące progi coverage dla krytycznej logiki i całego kodu po pomiarze baseline; nie zastępować jakości testów samym procentem.
- Dodać realistyczne testy awarii, współbieżności, late events, replay, restartu workerów, utraty transportu, retencji i odtwarzania snapshotów.
- Zmierzyć obciążenie na opisanym sprzęcie: przepustowość, p95 opóźnienia i limity pamięci/backlogu. Zapisać warunki pomiaru i granice lokalnego demo zamiast obiecywać skalę produkcyjną.
- Usunąć flakiness zegara i zależność od publicznych API; rozdzielić szybkie testy PR od dłuższej regresji.

**Artefakty:** raport testów i coverage, zestaw scenariuszy awaryjnych, baseline wydajności i instrukcja uruchomienia.

**Weryfikacja:** kompletna zielona regresja na czystym środowisku usług, lint/format/type checks, rzeczywiste migracje i frontend build. Każdy naprawiony defekt ma test tam, gdzie test wykrywa jego przyczynę.

**Ukończenie:** krytyczne ścieżki i negatywne przypadki mają mierzalny dowód; nie ma znanych czerwonych testów, a wynik jest powtarzalny według zapisanych komend.

## PHASE 18 — Documentation

**Zależności:** 1–17; dokumentacja była aktualizowana przy każdym przyroście.

**Zadania:**

- Ukończyć README: opis, stack, architektura/diagram, wymagania sprzętowe, instalacja, Docker, bootstrap użytkownika, demo, scenariusze, API, bezpieczeństwo i roadmap.
- Uzgodnić z kodem `architecture.md`, `detection-engine.md`, `correlation-engine.md`, `risk-engine.md`, `incident-response.md`, `threat-hunting.md`, `soar.md`, `security.md` i ADR.
- Dodać rzeczywiste screenshots UI z demo, dokumentację Sigma subset/query language, OpenAPI, migracji, backup/restore, retencji i rozwiązywania problemów.
- Spisać przewodnik prezentacji, ograniczenia MVP i świadome decyzje odłożone poza zakres.

**Artefakty:** kompletna dokumentacja użytkownika, dewelopera i operatora; zaktualizowana macierz wymagań z dowodami.

**Weryfikacja:** osoba odtwarzająca instrukcję startuje od czystego katalogu/środowiska; sprawdzenie komend, linków i zgodności screenshotów; kontrole dokumentów oraz smoke demo i dotkniętych testów.

**Ukończenie:** dokumentacja opisuje rzeczywiste zachowanie, rozróżnia działające funkcje i roadmap, a demonstracja nie wymaga wiedzy ukrytej w historii rozmowy.

## PHASE 19 — CI/CD

**Zależności:** 1–18; istnieją już bootstrap i kontrole bieżących przyrostów.

**Zadania:**

- Scalić GitHub Actions: lint, format, typy, unit/API/integration, detection regression, frontend/E2E, security/dependency scanning i Docker build.
- Przetestować migracje od pustej bazy i aktualizację ze wspieranej poprzedniej wersji; zbudować wszystkie wymagane obrazy i uruchomić Compose smoke.
- Nadać minimalne uprawnienia workflow, bezpiecznie obsłużyć cache/artefakty/sekrety i przypiąć zależności workflow zgodnie z przyjętą polityką.
- Ustawić wymagane kontrole dla PR w hostowanym repozytorium. Zdefiniować powtarzalny build wydania; publikacja/deployment nie są domyślnym celem lokalnego MVP.

**Artefakty:** komplet workflow, udokumentowane wymagane status checks, artefakty testów/build i proces wydania.

**Weryfikacja:** rzeczywisty przebieg GitHub Actions dla commita projektu, kontrolowana próba z celowo czerwonym testem na gałęzi testowej potwierdzająca blokadę PR, build/Compose smoke; analiza logów i uprawnień workflow.

**Ukończenie:** istnieje dowód zielonego hostowanego CI i blokowania PR przez podstawowe kontrole. Brak repozytorium zdalnego oznacza jawnie niezweryfikowaną część fazy, nawet jeśli lokalne polecenia są zielone.

## PHASE 20 — Final audit

**Zależności:** ukończone i zweryfikowane 0–19.

**Zadania:**

- Przejść wszystkie wymagania 1–37 i każde kryterium Definition of Done, przypisując plik, endpoint lub widok oraz test/komendę jako dowód.
- Wykonać czysty start Compose, bezpieczny bootstrap konta i wszystkie scenariusze przez ingestion, normalizację, detekcję, korelację, ryzyko, incident i SOAR.
- Zweryfikować frontend z realnym API, offline runtime demo, RBAC, audit, restart/replay, brak sekretów i brak rzeczywistych efektów infrastrukturalnych SOAR.
- Przeprowadzić 30–60 minutową próbę prezentacji, sprawdzić README/screenshots i opisać pozostałe ograniczenia oraz przyszłe prace.

**Artefakty:** raport końcowy z macierzą dowodów, wynikami testów, identyfikatorem wersji i jednoznacznym werdyktem.

**Weryfikacja:** pełna regresja, lint/format/typy, komplet scenariuszy E2E i powiązany zielony przebieg CI na audytowanej wersji; porównanie zgłoszonych możliwości z rzeczywistym działaniem.

**Ukończenie:** wszystkie punkty pełnego DoD z wymagania 37 są potwierdzone dowodami. Niezamknięty punkt oznacza nieukończony projekt; raport nie zastępuje brakującego modułu lub testu.

## Zasady aktualizacji planu

Zmiana kolejności lub zakresu wymaga aktualizacji zależności, macierzy wymagań i istotnego ADR. Mniejsze zadania można dzielić na osobne Conventional Commits. Fazy nie stanowią obietnicy terminu; estymacje powstaną po uruchomieniu fundamentu i zmierzeniu kosztu pełnego pionowego przyrostu. Przejście do kolejnej fazy powinno opierać się na dowodach z bramki, a nie na liczbie utworzonych plików.
