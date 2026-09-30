# Skrypty lokalnego uruchomienia i walidacji

Instrukcja użytkownika: [lokalny start](../docs/local-start.md).
Launcher [Uruchom Aegis.cmd](../Uruchom%20Aegis.cmd) wywołuje
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/aegis.ps1 -Action start`.
Ustawienie execution policy dotyczy tylko tego procesu PowerShell.

## Sterowanie na Windows

`aegis.ps1` działa względem katalogu projektu i używa projektu Compose `aegis-soc`.

| Akcja | Działanie |
| --- | --- |
| `start` | Zachowuje `.env` i dane, przygotowuje obraz, uruchamia usługi; przy braku kont prosi o hasło pierwszego administratora |
| `status` | Pokazuje stan usług i publiczne sondy; nie sprawdza pełnego przetwarzania |
| `admin` | Interaktywnie tworzy pierwszego administratora, domyślnie `admin` |
| `check` | Interaktywnie sprawdza aktualny przepływ ingestion z istniejącym administratorem |
| `stop` | Zatrzymuje usługi z zachowaniem wolumenów i konfiguracji |

Przykład z katalogu głównego repozytorium:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action status
```

`-Username` ustawia nazwę administratora przy pierwszym `start`, dla `admin` i `check`.
`-BuildMode auto|online|offline` wybiera sposób budowania przy `start`.
`auto` używa istniejącego wheelhouse lub próbuje online i przechodzi do offline
po niepowodzeniu, jeśli dostępny jest Python 3.12 z pip. Wynik startu i wynik
kontroli funkcjonalnej są osobnymi komunikatami. Hasło administratora jest
wprowadzane interaktywnie, bez pliku ze stałym hasłem. `-SkipAdmin` przy `start`
pomija tworzenie konta i monit hasła; `check -HealthOnly` sprawdza tylko gotowość.

## Konfiguracja i budowa offline

`bootstrap_env.py` tworzy lokalny `.env` z losowymi sekretami, niczego nie
nadpisuje i nie wypisuje wartości. Launcher może wykonać go w kontenerze,
bez Pythona na hoście. Samodzielne użycie:

```powershell
py scripts/bootstrap_env.py
```

`prepare_wheelhouse.py` wymaga Python 3.12 z pip. Pobiera przypięte wheel dla
Linux x86_64 do ignorowanego `backend/.wheelhouse`, z weryfikacją TLS i hashy
z lockfile. Budowa z `compose.offline.yaml` instaluje te same zależności przez
`--no-index --require-hashes`; brakujący lub zmieniony plik powoduje błąd.

```powershell
py -3.12 scripts/prepare_wheelhouse.py
docker compose -f compose.yaml -f compose.offline.yaml build api
docker compose -f compose.yaml -f compose.offline.yaml --profile test build tests
```

Pobranie wheel i brakujących obrazów bazowych wymaga dostępu do sieci.
„Offline” opisuje instalację zależności podczas budowy, nie pobieranie ich
po raz pierwszy ani kompletny pakiet instalacyjny bez Internetu.

## Kontrola działającego backendu

`check_runtime.py` używa biblioteki standardowej Pythona. Pełna kontrola
wymaga istniejącego administratora, pyta o hasło w ukrytym monicie i sprawdza
sondy, logowanie, źródło, trwały zapis, idempotencję i dojście do `staged`.
Po kontroli wyłącza tylko utworzone przez siebie źródło, odwołuje jego tokeny
i zamyka własną sesję. Syntetyczne zdarzenie, metadane źródła i audyt pozostają
w bazie; PHASE 2 nie ma jeszcze retencji ani endpointu usuwania.

```powershell
py scripts/check_runtime.py --username admin
py scripts/check_runtime.py --health-only
```

`--health-only` nie sprawdza relay/workera. Launcher może wykonać kontrolę
w kontenerze bez Pythona na hoście. Inne parametry opisuje
`py scripts/check_runtime.py --help`; żaden nie wymaga hasła w argumentach.

## Walidacja struktury repozytorium

`python scripts/validate_repository.py` (Windows: `py ...`) wymaga Python 3.11+.
Brak bibliotek zewnętrznych; skrypt niczego nie instaluje i nie zmienia plików.

Sprawdza wymagane katalogi/pliki z manifestu, UTF-8/LF/final newline, trailing
whitespace, domknięcie fenced code blocks, docelowe pliki lokalnych Markdown links,
składnię Python AST i numerację faz/wymagań. Ignoruje artefakty runtime i `.git`.
Jest to ograniczona bramka PHASE 0, nie pełny Markdown linter, test Mermaid,
skaner sekretów ani test aplikacji. Testy i bramki backendu opisuje
[instrukcja PHASE 1](../docs/phase1-operations.md), a zakres ingestion
[instrukcja PHASE 2](../docs/phase2-operations.md).
