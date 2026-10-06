# Walidacja Etapu 8 — Attack Timeline

Data: 2026-10-06. Punkt wyjścia: `0013c1d`.
Stan: Etap 8 wdrożony lokalnie; pełna regresja i kontrole uruchomienia oraz
restartu PASS. Zalogowany przebieg przeglądarkowy i pozostałe ograniczenia
opisuje punkt 8.
[Zakres](attack-timeline.md), [ADR 0014](adr/0014-observed-attack-timeline.md).

## 1. Zakres

Panel „Chronologia zdarzeń” pokazuje oryginalne dowody aktywnie przypiętych
alertów sprawy, od najstarszego czasu źródła. Deduplikuje eventy i zachowuje
wszystkie odniesienia do alertów, także oznaczonych jako fałszywy alarm.
Każdy wpis otwiera zachowany log w istniejącym widoku zdarzenia. Historia pracy
analityka ma osobny panel.

API zachowuje mikrosekundy czasu i jawny zakres live/replay. Panel pokazuje
niepełność starszego indeksu oraz przypadek zastąpienia czasu źródła czasem
przyjęcia. Kontrole źródła, podpisanego kursora i bieżącej sesji chronią odczyt
oraz kolejne strony. Linia przedstawia kolejność obserwacji; wnioski o etapach
ataku pozostają decyzją analityka.

## 2. Dodane pliki

Łącznie **18 nowych plików**:

- Backend: router, pięć plików modułu `attack_timeline`, dwa pliki testów
  jednostkowych, dwa integracyjnych i wspólny helper — 11 plików.
- Panel: komponent `AttackTimeline`, hook `useAttackTimeline`, testy
  i wspólne fixtures — 4 pliki.
- Dokumentacja: kontrakt chronologii, niniejszy raport i ADR 0014 — 3 pliki.

## 3. Zmienione pliki

Łącznie zmieniono **23 istniejące pliki**:
rejestrację routera, szczegóły incydentu, tytuł historii analityka, typy i style,
fixtures dotychczasowych widoków oraz kontrakty, plan i manifest repozytorium.
Compose używa obrazów `timeline-stage8`. Cały przyrost obejmuje **41 plików**.

## 4. Endpointy

Jedna nowa ścieżka i metoda:
`GET /api/v1/incidents/{incident_id}/attack-timeline?limit=25&cursor=...`.
Wymagane łącznie `incidents:read`, `alerts:read` i `events:read`.

Strona zawiera 1–25 zdarzeń, domyślnie 25. Podpisany kursor wiąże użytkownika,
sprawę, limit, fingerprint i ostatni klucz sortowania; wygasa po 15 minutach
od pierwszej strony. Odpowiedź ma `Cache-Control: no-store`. Odczyt ma limit
60 żądań na minutę i 3 s czasu SQL. Budżet wybranej strony wynosi 4 MiB.
Zmiana widoku, niespójny dowód i przekroczenie limitu zwracają jawne błędy 409.

## 5. Modele

Nowe DTO projekcji `attack-timeline-v1` i kursora korzystają z istniejących
Incident/IncidentAlert/Alert, EntityAlertReceipt/AlertEventReference oraz
RawEvent/NormalizedEvent. Odpowiedź zachowuje wersję sprawy, zakres,
fingerprint, licznik znanych eventów, stan indeksu, snapshoty zdarzeń i wszystkie
odnośniki alertów. Jedno zapytanie wyznacza metadane, indeks i stronę.
Brak nowej tabeli, migracji lub usługi; head pozostaje `0011_intelligence`.

## 6. Nowe testy

Backend dodaje **96 przypadków: 50 unit i 46 integration**. Obejmują kolejność
i mikrosekundy, przyszły/spóźniony czas, wspólne dowody wielu alertów, FP,
zakres live/replay, niepełny i uszkodzony indeks, stronicowanie, zmianę danych
między stronami, uszkodzone raw/normalized/kopie oraz podpis, ważność i zakres
kursora. Sprawdzają również uprawnienia, limity i rzeczywiście dużą legalną
stronę źródłową.

Panel dodaje **32 przypadki**, w tym otwarcie oryginalnego logu, zachowanie
kolejności API, stany pusty/pending/błąd, zmianę sprawy i uprawnień, anulowanie
żądań oraz odrzucanie opóźnionych odpowiedzi i kliknięć poprzedniej sesji.
Zebrany zestaw backendu liczy **1420 unit + 642 integration = 2062**;
pełny zestaw panelu liczy **238**. Wszystkie te przypadki przeszły końcowe kontrole.

## 7. Wyniki kontroli

Pełna regresja Linux i odbiór głównego wdrożenia zakończone poprawnie.

| Kontrola | Potwierdzony wynik |
| --- | --- |
| Wszystkie testy jednostkowe backendu — Windows | **1420 PASS**, 642 integracje wyłączone, 42,29 s |
| Nowe testy jednostkowe chronologii | **50 PASS**, 1,39 s |
| Nowe integracje — pierwszy przebieg końcowego kodu | **45 PASS / 1 FAIL**, 96,85 s; poprawka danych wejściowych testu opisana niżej |
| Ponowienie testu dużej strony | **1 PASS**, 13,45 s |
| Chronologia — unit i integration z coverage | **96 PASS**, 291,70 s; 100% zmierzonego kodu Python modułu i routera |
| Panel — pełny przebieg | **238 PASS**, 11 plików, 35,41 s |
| TypeScript / ESLint / Prettier | PASS |
| Ruff / format / MyPy w obrazie | PASS; 196 plików sformatowanych, 125 źródeł MyPy; Ruff/format ponowione po poprawce fixture: PASS |
| Pip check | Brak konfliktów zainstalowanych zależności; bez oceny podatności |
| Skrypty | **32 przypadki pytest PASS**, 2,56 s |
| Obrazy runtime i tests | Offline build PASS |
| Alternatywny build panelu | PASS; 101 modułów, 736 ms |
| Pełny backend Linux/Python 3.12.14 | **2062 PASS** w pięciu rozłącznych partiach; bez pominięć |
| Świeża instalacja | **0011_intelligence**; health/ready/OpenAPI/root/JS 200; metoda GET chronologii obecna; anonimowy odczyt 401; CSP self-only |
| Główny launcher | Standardowy offline start z `-SkipAdmin` PASS; 93 pakiety z potwierdzonymi hashami; panel i backend zbudowane poprawnie |
| Główne dane i schemat | `0011_intelligence`, wcześniejsze liczniki i cały plik `.env` bez zmian |
| Główne HTTP i panel | health/ready/OpenAPI/root/JS 200; nowa chronologia w API i JS; anonimowe żądania 401; CSP self-only |
| Restart processor/detector/correlator | PASS: nowe StartedAt, Running=true i wspólny obraz z API |
| Porządek po testach | 0 baz `aegis_test_%`; instalacja testowa zatrzymana, wolumeny zachowane; główna aplikacja uruchomiona |
| Repozytorium i dokumentacja | PASS: 433 pliki tekstowe, 46 katalogów, 21 faz, 37 wymagań, 14 ADR; git diff --check PASS |

Pierwszy przebieg 46 integracji wykrył błąd przygotowania testu dużej strony:
25 poprawnych zdarzeń, każde z 65 000 bajtów raw, przesłano jednym żądaniem
przekraczającym limit ingestion 1 MiB. Test nie dochodził do odczytu chronologii.
Fixture przyjmuje teraz te same zdarzenia w partiach 10/10/5; kod aplikacji
pozostał bez zmian. Ponowienie potwierdziło odrzucenie strony ponad 4 MiB
i poprawny odczyt pojedynczego eventu. Pełna regresja zawiera poprawiony test.

Focused kontrole częściowo nakładają się na większe zestawy i nie są sumowane
do wyniku pełnej regresji. Wszystkie konta fixtures istnieją wyłącznie
w losowych bazach testowych.

Pomiar coverage z zielonego zestawu 96 przypadków dotyczy wyłącznie nowego
modułu `app.modules.attack_timeline` i routera `app.api.attack_timeline`:
**100%**, 176 instrukcji i 30 gałęzi, bez brakujących instrukcji i częściowo
pokrytych gałęzi. Nie jest pomiarem pokrycia całej aplikacji ani wnętrza SQL;
rzeczywiste zapytania PostgreSQL sprawdzają testy integracyjne.

Jednolity przebieg 2062 testów został przerwany kodem 137 bez końcowego wyniku.
W tym samym czasie logi Dockera zapisały żądania zatrzymania kontenerów
z interfejsu Docker Desktop. Nie znaleziono śladów wyczerpania pamięci.
Ponowienie dzieli pełną zebraną listę testów na rozłączne partie, zachowując
wszystkie przypadki; każdy wynik został zapisany osobno. Końcowe partie:
integration-1: 160 PASS / 518,11 s; integration-2: 162 PASS / 514,66 s; integration-3: 161 PASS / 497,13 s; integration-4: 159 PASS / 538,45 s; unit: 1420 PASS / 35,86 s.
Partie integracyjne wykonywały się równolegle; ich czasów nie sumuje się
do czasu ściennego. Wynik 2062 jest sumą rozłącznych przypadków z manifestu.

Alternatywny build panelu ma JS `index-DixKL-sK.js`, 432,21 kB/gzip 120,70 kB,
oraz CSS `index-C6JHwBd3.css`, 21,72 kB/gzip 5,56 kB. Standardowy build launchera
powtórzył te zasoby w 572 ms; główna instalacja udostępnia nowy JS chronologii.

Osobna instalacja `aegis-timeline-20261005` na porcie 18087 ma własne sekrety
i wolumeny. Ma head `0011_intelligence`, users i sprawdzane dane domenowe 0,
jedną publikację reguły TI, bez kont i demo. Odczyt HTTP potwierdził również
zachowanie ośmiu ścieżek i dziesięciu metod TI oraz nowy JS chronologii.

Source hash local/runtime/test/fulltest/fresh/main:
`4576325b78481c28a51b8eb8fc5c8aff107849c8b6f3425b5df695ca6ea72556`.
Obejmuje backend Python, migracje, lokalny katalog MITRE i licencję,
z normalizacją LF; nie obejmuje UI, testów ani zależności. Zgodność głównej
instalacji została potwierdzona po wdrożeniu. API oraz zrestartowane procesy
korzystają z obrazu `sha256:83b2d68631eb66c6fee5b495b8b427c7afe3ee583f0c16cc9c0c7dca7e43d843`.
Główna aplikacja działa pod `http://localhost:8080`. Logi i dowody znajdują się
w ignorowanym `.local/timeline` i `.local/attack-timeline`.

## 8. Ograniczenia i problemy

Weryfikacja pełnego oryginalnego dowodu dotyczy pobranej strony. Starszy brak
receiptu jest pending, a administrator ma istniejącą operację backfill.
Chronologia obejmuje dowody aktywnie przypiętych alertów; odpięte dowody są
w istniejącej historii sprawy. Granica zaufanego writera i administratora DB
pozostaje zgodna z wcześniejszymi etapami.

Fingerprint wykrywa zmiany wersji, aktywnych powiązań, statusów alertów i indeksu
między stronami; nie jest wielożądaniową transakcją MVCC. Panel może wymagać
odświeżenia widoku. Nie wykonano testu wydajności granicy 100 alertów dzielących
jeden dowód; testy poprawności obejmują współdzielone odniesienia.

Docker Desktop przerwał początkową budowę i blokował obsługę poleceń.
5 października odzyskanie komunikacji wymagało ograniczonego zatrzymania jego
dystrybucji WSL. Po ponownym wyłączeniu środowiska, 6 października wystarczyło
odtworzenie dwóch katalogów komunikacji z zachowaniem ich kopii. Nie usuwano
wolumenów danych. Po odzyskaniu komunikacji wykonano końcowe budowy offline. Kontrola stanu
głównej instalacji po tej naprawie zachowała schemat `0011_intelligence`, zerowe
liczniki użytkowników i sprawdzanych danych domenowych oraz jedną publikację
reguły TI. Jest to dowód zachowania poprzedniej instalacji, nie odbioru Etapu 8.

Automatyczna kontrola zatwierdzeń wcześniej odrzuciła utworzenie administratora
głównej instalacji jako zmianę uprawnień. Wdrożenie używa `-SkipAdmin`, a konta
fixtures istnieją tylko w losowych bazach testowych. Pełny zalogowany przebieg
przeglądarkowy pozostaje otwarty. Pierwsze konto użytkownik tworzy ukrytym monitem
[Uruchom Aegis.cmd](../Uruchom%20Aegis.cmd).

Automatyczna kontrola odrzuciła również internetowy skan zależności przesyłający
nazwy i wersje 48 pakietów do PyPI; pozostaje otwarty. Lokalny pip check sprawdza
zgodność pakietów. Hostowane CI i pełne Definition of Done platformy są otwarte.
OneDrive nie jest uruchamiany po wcześniejszej odmowie automatycznej kontroli;
budowa korzysta z istniejących lokalnych zależności.

## 9. Następny etap

Etap 9: UEBA — deterministyczne baseline i statystyki aktywności,
obserwacja/baseline/wyjaśnienie anomalii, jawny cold start i izolacja replay.
