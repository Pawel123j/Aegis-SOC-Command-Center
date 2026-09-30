# Walidacja lokalnego uruchomienia

Kontrole: 2026-09-30 oraz 2026-10-01; końcowy full check wykonano 2026-10-01.
Zakres: start z folderu na Windows, budowanie obrazów,
konfiguracja, kontrola działającego backendu i zachowanie danych przy restarcie.
Obejmuje istniejące funkcje PHASE 1–2. Normalizacja, wyszukiwanie, detekcje,
alerty i panel SOC nadal wymagają kolejnych faz.

## Wykonane kontrole

| Kontrola | Wynik |
| --- | --- |
| Standardowy Dockerfile i `compose.offline.yaml` | API oraz tests zbudowane poprawnie; bez generowanego Dockerfile walidacyjnego |
| Pakiety Linux/Python 3.12 | 91 przypiętych pakietów; hashe sprawdzone względem obu lockfile |
| Ponowne użycie pakietów | Kompletny cache działa bez pobierania; test zabraniający wywołania downloadera: PASS |
| Brakujący pakiet | Rzeczywiste pobranie jednego przypiętego pakietu do oddzielnego cache, z TLS i kontrolą hash: PASS |
| Pierwsza konfiguracja | Bootstrap w kontenerze tworzy `.env`; druga próba odmawia nadpisania, skrót pliku bez zmian: PASS |
| Pierwszy start usług | `aegis.ps1 -Action start -BuildMode offline -SkipAdmin`: PASS; migrator exit 0, bazy i API gotowe |
| Sterowanie spoza folderu | `status` wywołany z nadrzędnego katalogu: PASS; ścieżki wynikają z położenia skryptu |
| Zatrzymanie i ponowny start | `stop`, następnie `start -BuildMode auto -SkipAdmin`: PASS; konfiguracja oraz wszystkie trzy nazwane wolumeny zachowane |
| Pełny przepływ z Windows | PASS: logowanie administratora, źródło, HTTP 202, powtórzona idempotentna odpowiedź i `staged` przez relay/worker |
| Pełny przepływ z kontenera | PASS: oficjalny Python 3.12.14, `host.docker.internal:18080`, oddzielny Origin i hasło Unicode przez stdin |
| Sprzątanie zasobów kontroli | Oba własne źródła wyłączone, ich credentiale odwołane i sesje zamknięte; liczniki własnych danych: 2 raw, 2 receipts i 2 staged |
| Testy nowych helperów | **19 testów PASS**: 12 kontroli runtime i 7 kontroli wheelhouse; biblioteką standardową, oddzielnie od historycznych 454 testów backendu |
| Tymczasowy stos | `aegis-startup-smoke-20260930` i jego trzy potwierdzone wolumeny usunięte; właściwy projekt oraz jego dane zachowane |
| PowerShell 5.1 | Parser: PASS; sprawdzone argumenty sondy kont i UTF-8 dla hasła z polskim znakiem |
| Python | Ruff lint/format według konfiguracji backendu: PASS dla nowych helperów, ich testów i zmienionego walidatora |

Kontrola statusu rozróżnia gotowość API i zależności od przetwarzania zdarzeń.
Wynik health-only nie deklaruje działania relay ani workera.

Pełne kontrole użyły osobnego projektu na porcie 18080 i losowego hasła
testowego przechowywanego tylko w pamięci. Nie zmieniały kont ani danych
właściwej instancji. Każda kontrola tworzy swoje źródło, zdarzenie i sesję;
samodzielny `check` zachowuje syntetyczny ślad w bazie zgodnie z instrukcją.

Weryfikacja wykryła i naprawiła dwa problemy klienta kontrolnego: domyślny
form content type dodawany przez urllib do pustych POST powodował 415 dla
refresh/logout, a limit 3 s był zbyt krótki dla sekwencyjnej sondy zależności.
Puste mutacje jawnie wysyłają JSON, operacje kontrolne mają limit 10 s,
a polling zdarzenia zachowuje odrębny deadline. Testy obejmują też odświeżenie
własnej sesji przed cleanup oraz zachowanie bezpiecznej przyczyny błędu.

## Sposób uruchomienia

Z tego folderu można kliknąć dwukrotnie `Uruchom Aegis.cmd`.
Pierwszy interaktywny start prosi o własne hasło administratora, gdy baza nie
ma użytkowników. Start wykonany przez agenta użył `-SkipAdmin`: bieżący
projekt `aegis-soc` działa pod `http://localhost:8080`, a użytkownik może ustawić
hasło przy pierwszym normalnym uruchomieniu. Nie utworzono stałego hasła demo.

Instrukcja: [lokalny start](local-start.md). Kontrakt, funkcje i ograniczenia
backendu: [raport PHASE 2](validation.md).

Tryb offline dotyczy instalacji zależności w obrazie. Pierwsze przygotowanie
pakietów i brakujących obrazów bazowych wymaga Internetu. Na tym hoście
pobieranie PyPI bezpośrednio z kontenera nadal zależy od jego zaufania CA;
obsługiwana ścieżka wykorzystuje zaufane certyfikaty Windows przy przygotowaniu
pakietów, a następnie instaluje je lokalnie z obowiązkowymi hashami.
TLS pozostaje włączony, a wersje zależności nie zostały zmienione.

## Zakres dowodu

Historyczna regresja backendu pozostaje opisana oddzielnie: 454 testy i 91%
pokrycia w raporcie PHASE 2. Dodanie launchera nie oznacza ukończenia dalszych
faz ani potwierdzenia hostowanego CI. Nie wykonano publikacji ani push.
