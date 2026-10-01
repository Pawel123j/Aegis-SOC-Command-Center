# Pierwsze alerty i panel SOC

Zakres historycznego przyrostu `6119335`. Późniejszy
[Etap 1](incidents.md) dodaje działające incydenty, notatki, dowody i timeline.
Opisy „przyszłe” w tym dokumencie dotyczą stanu przed tą rozbudową.

Ten przyrost udostępnia działające moduły przez wspólny lokalny panel pod
[localhost:8080](http://localhost:8080). PHASE 0–3 są zakończone; pełne fazy
detekcji, explainability i UI pozostają otwarte. Wyniki:
[walidacja bieżącego przyrostu](validation-initial-soc.md).

## Trzy reguły, które działają

| Reguła | Wymagany dowód | Czego wynik nie potwierdza |
| --- | --- | --- |
| `powershell-suspicious-command` | Windows 4688 lub Sysmon 1: rzeczywisty proces PowerShell/pwsh z kodowanym parametrem albo rozpoznanym pobieraniem i wykonaniem w command line | Sukcesu ataku, pełnej interpretacji PowerShell, treści pliku skryptu |
| `linux-root-session` | Zaakceptowane sudo z bezpośrednią powłoką root albo otwarcie sesji su do root przez nie-rootowego użytkownika | Wykorzystania podatności; log su potwierdza sesję, nie wykonanie powłoki |
| `windows-local-admin-member-added` | Windows 4732 z SID grupy `S-1-5-32-544` | Utworzenia konta, sekwencji kilku zdarzeń, tożsamości nieobecnej w logu |

Każda reguła ma wersję 1.0.0, opis, severity, guidance, odnośniki i zachowany
snapshot. Linux root session celowo nie otrzymuje automatycznego mapowania MITRE
na exploit. Dwie reguły Windows mają odpowiednio T1059.001 i T1098.007.

Detekcje są czyste: bez I/O, wykonywania poleceń, LLM i okien zegara. Obsługiwany
podzbiór nie jest silnikiem Sigma ani threshold/sequence. Polityka dalszych
reguł czasowych pozostaje w [ADR 0004](adr/0004-detection-semantics.md).

## Trwałość i decyzje analityka

Osobny proces `app.detector` odczytuje niezmienne snapshoty PostgreSQL,
sprawdza SHA-256 i kontrakt, a potem zapisuje alert, dowód, audyt i checkpoint
w jednej transakcji. Powtórzenie tego samego eventu/reguły/wersji/scope nie
tworzy drugiego alertu. Awaria ClickHouse nie blokuje tej pracy. Niespójna
wersja lub brak deploymentu pozostawia checkpoint pending; uszkodzony dowód
otrzymuje quarantine i bezpieczny kod błędu.

Administrator i SOC Manager mogą włączać/wyłączać trzy reguły. Zmiana dotyczy
przyszłych, jeszcze nieprzetworzonych rekordów. Nie usuwa historycznych alertów
i nie uruchamia automatycznie ponownej ewaluacji. `version` jest numerem edycji
deploymentu; `rule_version` oznacza definicję reguły.

SOC Analyst/Manager/Admin mogą potwierdzić alert, oznaczyć false positive lub
resolved. Każda decyzja wymaga `If-Match`, podlega RBAC i zapisuje audit.
Pierwszy czas/osoba potwierdzenia pozostają zachowane. Snapshot reguły,
eventu, powód i hash mają granty uniemożliwiające runtime UPDATE/DELETE.
Risk score jest **null**, ponieważ nie wdrożono jeszcze silnika ryzyka.

## Korzystanie z panelu

1. Uruchom [launcher](local-start.md) i ustaw swoje pierwsze konto administratora.
2. Zaloguj się do panelu. W „Źródła logów” wybierz nazwę, strefę czasu i formaty.
3. Zapisz wydany klucz. Możesz przesłać pojedynczy log albo batch envelope.
   Pojedynczy log używa jawnego czasu wysłania; dla timestampu źródłowego użyj
   batch envelope. Ponowienie zachowuje identyczny body i Idempotency-Key.
4. Status odróżnia przyjęcie, normalizację, archiwizację i checkpoint detekcji.
5. W Event Explorer wyszukaj zdarzenie i otwórz oryginalny log oraz provenance.
6. W „Alerty” sprawdź powód dopasowania i dowód; odpowiednia rola może zmienić status.
7. W „Reguły detekcji” sprawdź opis albo przetestuj pełne normalized events.
   Test jest czysty, nie tworzy alertów; limit 100 rekordów i 64 KiB body.

Panel pokazuje tylko dostępne funkcje. Incydenty, storyline, hunting z zapisami,
IOC, SOAR, risk i generator siedmiu scenariuszy pozostają dalszymi etapami.
Klucze źródeł i access JWT są wyłącznie w pamięci przeglądarki. Zasady sesji:
[ADR 0005](adr/0005-frontend-and-auth.md).

## API i status

| Endpoint | Uprawnienie / zachowanie |
| --- | --- |
| `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}` | `alerts:read`; filtry i podpisana paginacja; niezmienny dowód |
| `PATCH /api/v1/alerts/{id}` | `alerts:manage`; status, If-Match, atomic audit |
| `GET /api/v1/detections`, `GET /api/v1/detections/{id}` | `detections:read`; katalog trzech reguł i deployment |
| `PATCH /api/v1/detections/{id}` | `detections:publish`; enabled, If-Match, atomic audit |
| `POST /api/v1/detections/test` | `detections:test`; id + events, czysta ewaluacja |
| `GET /api/v1/system/detections` | `system:read`; rzeczywiste checkpointy i wiek backlogu |

Collector credential nie uprawnia do odczytu alertów, reguł ani wyszukiwania.
Batch status podaje `counts.processed` oraz `detection_state` dla każdego
rekordu. `processed` oznacza ocenę aktywnymi regułami, również bez dopasowania.

Nie ma retencji dowodów, operacyjnego detekcyjnego retry UI ani backfill
historycznych eventów po zmianie deploymentu. Reguły czasowe, migracja katalogu
i polityka ponownej ewaluacji wymagają osobnego zaprojektowanego przyrostu.
