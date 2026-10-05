# Walidacja Etapu 7 — Threat Intelligence i IOC

Data: 2026-10-05. Punkt wyjścia: `b8b14a1`.
Stan: Etap 7 wdrożony lokalnie; końcowa regresja oraz kontrole migracji,
uruchomienia i restartu PASS. Zalogowany przebieg przeglądarkowy pozostaje
otwarty, zgodnie z punktem 8. [Zakres](intelligence.md), [ADR 0013](adr/0013-local-intelligence.md).

## 1. Zakres

Lokalny katalog IP/domain/URL/hash, niezmienne rewizje reputacji i metadanych,
provider interface, exact lookup, atomowy import JSON, panel i utrwalone
dopasowania w szczegółach zdarzenia. Malicious match tworzy medium TI alert
i zwiększa priorytet przez odrębny komponent I. Jawny backfill obejmuje tylko
eventy bez receipt; brak zewnętrznego lookup albo wykonania URL.

## 2. Dodane pliki

Moduł intelligence (dziewięć plików), router, migracja 0011, risk engine_v4,
dziewięć plików testów backendu, czternaście plików panelu intelligence,
dwa pliki testów panelu, dokumentacja intelligence i niniejszy raport oraz ADR 0013.
Łącznie **40 nowych plików**.

## 3. Zmienione pliki

Łącznie **45 istniejących plików**. Integracja detector/risk/MITRE/entity
projections, model/router registration,
readiness, body validation, jawna istniejąca zależność idna, frontend nawigacja
i event/alert proof, historyczne migration fixtures, Compose i dokumentacja.
Launcher po jawnym frozen/offline install nie uruchamia kolejnego implicit
install pnpm 11 przed build. Ten dodatkowy krok gubił ustawienia lokalnego
cache/offline i mógł próbować podmiany zależności; końcowy standardowy start
offline potwierdził poprawkę.
Zmiana obejmuje również historyczny test symulacji IOC, który sprawdza teraz
jednocześnie niezmienione v3 i nowe v4. Cały przyrost obejmuje **85 plików**.
Idna 3.20 jest jawną zależnością; była już w lockfile, a wersje i hashe
pakietów pozostały bez zmian.

## 4. Endpointy

Osiem ścieżek, dziesięć metod pod `/api/v1/intelligence`:

| Metoda | Ścieżka | Działanie |
| --- | --- | --- |
| GET / POST | `/iocs` | Katalog / utworzenie IOC |
| GET / PATCH | `/iocs/{ioc_id}` | Odczyt / nowa rewizja z If-Match |
| GET | `/iocs/{ioc_id}/history` | Oryginalne rewizje |
| POST | `/import` | Atomowy import do 100 |
| POST | `/lookup` | Dokładne lokalne sprawdzenie |
| GET | `/providers` | Dostępny provider lokalny |
| GET | `/events/{event_id}` | Zachowane field matches albo pending |
| POST | `/backfill` | Jawna jedna partia brakujących receipts |

Odczyt: intelligence:read; zapis: intelligence:manage; event proof wymaga
także events:read; backfill wymaga system:manage. Risk policy API opisuje v4
z fallback v3; istniejące explicit recalculation endpoints zachowują historię.

## 5. Modele

IOCIdentity, IOCRevision, IntEventReceipt i IntEventMatch. Append-only revision
ledger, kanoniczny JSON/SHA256, kontrolowana publikacja pointer, scoped immutable
receipts i FK/cardinality guards. Alert TI korzysta z istniejących Alert,
DetectionJob, RiskCalculation i unmapped AlertMitreSnapshot. Nie ma nowej usługi.

## 6. Nowe testy

Unit: ścisła normalizacja/IDNA/IP/URL/hash, typed extraction/provider,
metadata/revision proof i ręczna punktacja risk-v4. Integration: katalog/import,
rewizje/preconditions/RBAC, oryginalny source/ledger, trwałe zero matches,
malicious alert/risk, cofnięcie reputacji, replay, rollback, runtime SQL i migracje.
Frontend: API/permissions/session, konflikty, zachowane dowody i jednopartiowy backfill.

Nowy backend dodaje **419 przypadków**: 334 unit i 85 integration.
Końcowy zestaw zawiera **1370 unit + 596 integration = 1966** przypadków,
wobec 1547 w Etapie 6. Panel dodaje **58 przypadków** do wcześniejszych 148,
łącznie **206**. Testy panelu obejmują również zachowanie mikrosekund czasu
przy edycji innych pól oraz tagi z literalnym przecinkiem.

## 7. Wyniki kontroli

Pełna regresja backendu i kontrole głównego wdrożenia zakończone:

| Kontrola | Wynik |
| --- | --- |
| Pełny backend — końcowy przebieg Linux/Python 3.12.14 | **1966 PASS**, 1242,03 s (20 min 42 s), bez pominięć, bez instrumentation coverage |
| Panel — pełny końcowy przebieg | **206 PASS**, 36,74 s, dziesięć plików, dwa workers |
| TypeScript / ESLint / Prettier | PASS |
| Ruff / format / MyPy w końcowym obrazie | PASS; 185 plików sformatowanych, 119 źródeł MyPy |
| Pip check | Brak konfliktów zainstalowanych zależności; nie jest to skan podatności |
| Skrypty | **32 przypadki pytest PASS** z 20 subtests, 2,00 s |
| Focused catalogue / pipeline / storage | **40 PASS**, 62,81 s |
| Focused security / stare blokady migracji | **62 PASS**, 112,19 s |
| Poprawiony test v3/v4 i eligibility IOC | **5 PASS**, 6,66 s |
| Runtime i tests | Offline build PASS, bez zmiany przypiętych wersji pakietów |
| Osobna instalacja | **0011_intelligence**; health/ready/OpenAPI/root/JS 200; osiem ścieżek i dziesięć metod TI; anonimowe żądania 401; CSP self-only |
| Główny launcher | Standardowy offline start z `-SkipAdmin` PASS; 93 pakiety wheelhouse z poprawnymi hashami; poprawiony pnpm build PASS |
| Główny upgrade | **0010_entities → 0011_intelligence** PASS; wcześniejsze liczniki danych i cały plik konfiguracji bez zmian |
| Główne HTTP / panel po restarcie | health/ready/OpenAPI/root/JS 200; osiem ścieżek i dziesięć metod TI; anonimowe żądania 401; CSP self-only |
| Restart processor/detector/correlator | PASS; nowe StartedAt, Running=true, wspólny obraz z API |
| Porządek po testach | 0 baz `aegis_test_%`; stos walidacyjny zatrzymany, wolumeny zachowane; główny stos uruchomiony |
| Repozytorium i dokumentacja | PASS: 415 plików tekstowych, 45 katalogów, 21 faz, 37 wymagań, 13 ADR; git diff --check PASS |

Focused zestawy częściowo nakładają się i nie są sumowane do wyniku pełnej
regresji. Wszystkie konta fixtures istnieją wyłącznie w losowych bazach testowych.

Pierwszy pełny przebieg z coverage dał **1965 PASS / 1 FAIL**, 2330,57 s
(38 min 50 s). Jedyny FAIL był starym oczekiwaniem symulacji v3: malicious
z confidence 79 miało dawać I0. Endpoint z takim kontekstem wybiera teraz
wersjonowane v4 z wymaganym I5. Poprawiony test wymaga obu wyników:
v3 nadal score45, v4 score50, właściwy I i policy version/hash, zachowując
odmowę udziału nieaktywnych i wygasłych faktów. Kod aplikacji nie zmienił się.
Końcowy pełny przebieg został ponowiony w obrazie zawierającym poprawiony test:
wszystkie **1966 PASS**. Focused pięć przypadków nie zastępuje pełnej regresji.

Pomiar coverage z pierwszego przebiegu: **93%**, 8577 statements i 2132 branches.
Dotyczy tego samego kodu aplikacji, z jednym nieaktualnym oczekiwaniem testu;
nie jest przedstawiony jako pomiar z zielonego przebiegu. Pokrycie osobnych
procesów ma dowód integracyjny, bez deklaracji ich instrumentation coverage.

Standardowy build panelu: 99 modułów, 370 ms; alternatywny build 666 ms.
Oba mają JS `index-BcUcQClR.js`, 421,93 kB/gzip 118,19 kB oraz CSS
`index-DT5MqAWn.css`, 20,38 kB/gzip 5,36 kB. HTTP main/fresh potwierdziło nowy JS.

Osobna instalacja `aegis-intelligence-20261005` na porcie 18086 miała własne
sekrety i wolumeny. Po wcześniejszym próbnym schema 0011 wykonano wyłącznie
jej pusty downgrade do 0010 i upgrade końcowej migracji; historia nie istniała
i nie została usunięta. Fresh oraz main mają users i sprawdzane dane domenowe
oraz IOC/receipts/matches 0, jedną stałą publikację reguły TI, bez kont i demo.
Stan main przed upgradem: 0010, te same zerowe liczniki. Kontrola sumy pliku
`.env` przed/po potwierdziła zachowanie konfiguracji bez ujawniania zawartości.
Główna aplikacja działa pod `http://localhost:8080`.

Source hash local/runtime/fresh/fulltest/finaltest/main:
`2dfed60cd4ce87fa6a396780f011ceddfcccf1f7bfe0298bac4bb5e1020e5b80`.
Obejmuje backend Python, migracje, lokalny katalog MITRE i licencję,
z normalizacją LF; nie obejmuje UI, testów ani zależności. Główne API i trzy
zrestartowane procesy mają obraz
`sha256:a4f958e26e21a4f131b18ca4c076a7639084f3e0a92f833f7396ecbca071d5af`.
Główna instalacja została zbudowana offline z przypiętych zależności.
Logi i dowody są w ignorowanym `.local/intelligence`; nie trafiają do commitu.

## 8. Problemy i granice dowodu

Nie wykonano zalogowanego przebiegu przeglądarkowego głównej aplikacji:
automatyczna kontrola odrzuciła utworzenie administratora jako zmianę uprawnień
bez osobnej zgody. Pierwsze konto użytkownik tworzy przez launcher w ukrytym monicie.
Nie uruchomiono OneDrive: auto-review odrzucił wznowienie synchronizacji bez
jednoznacznego zakresu danych/odbiorcy. Użyto istniejących lokalnych cache/runtime.
Nie wykonano internetowego skanu podatności zależności: odrzucono wysłanie
48 nazw i wersji do PyPI bez osobnej zgody. Pip check nie jest takim skanem.
Główny launcher sprawdził health/readiness, a nie uwierzytelniony przepływ
ingestion → relay → worker. Ten przepływ ma odrębny dowód integracyjny.
Hostowane CI pozostaje niezweryfikowane.

Reputacja/confidence są deklaracją źródła. Domain pochodzi tylko z poprawnego
typowanego URL host; schema 1.0 nie ma DNS domain. Historia match jest związana
z pierwszą analizą, nie historycznym czasem katalogu. INSERT pozostaje granicą
zaufanego writera; DB owner nie jest objęty forensic WORM. Cursor timestamp
nie gwarantuje wspólnej migawki kolejnych stron. Bounded risk selection ujawnia truncation.

## 9. Następny etap

Etap 8: Attack Timeline — graficzna chronologia obserwacji z czasem zdarzenia,
oryginalnymi dowodami, zakresem live/replay i jawnym oddzieleniem hipotez od faktów.
