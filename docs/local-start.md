# Lokalny start z folderu na Windows

Uruchomienie obejmuje wszystkie obecnie zaimplementowane usługi PHASE 1–2:
API, PostgreSQL, Redis, ClickHouse, migracje, relay, worker i lokalne proxy.
Dostępne są logowanie i role, zarządzanie użytkownikami, audyt, źródła,
credentiale ingestion, przyjmowanie surowych zdarzeń, status, retry i kwarantanna.
Stan `staged` oznacza przygotowanie do kolejnego etapu. Normalizacja, wyszukiwanie,
detekcje, alerty, incydenty i dashboard pozostają w planie dalszych faz.

## Pierwsze uruchomienie

1. Uruchom Docker Desktop z kontenerami Linux i poczekaj na gotowość silnika.
2. W folderze projektu kliknij dwukrotnie [Uruchom Aegis.cmd](../Uruchom%20Aegis.cmd).
3. Poczekaj na zbudowanie obrazu, migracje i potwierdzenie gotowości usług.
4. Gdy launcher poprosi o hasło pierwszego administratora, podaj i potwierdź
   własne hasło długości 15–128 znaków. Zapisz je w swoim
   menedżerze haseł. Domyślna nazwa konta to `admin`; własną można ustawić
   przy starcie przez `-Username nazwa`.
5. Otwórz PowerShell w folderze projektu i sprawdź przyjmowanie zdarzeń,
   używając tego konta:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action check
   ```

Pierwszy start może trwać dłużej, ponieważ pobiera obrazy i zależności.
Zwykły start online nie wymaga Pythona na Windows. Skrypt generuje `.env`
wyłącznie, gdy go brakuje; kolejne uruchomienia zachowują sekrety i dane.
`admin` tworzy konto tylko wtedy, gdy baza nie ma użytkowników; istniejące
konta pozostawia bez zmian. Kolejne konta tworzy administrator przez API.
Jeśli używasz własnej nazwy konta, dodaj `-Username nazwa` także do `check`.

API jest dostępne pod `http://localhost:8080/api/v1`; sondy to `/health`
i `/ready`. Nie ma jeszcze interfejsu przeglądarkowego pod głównym adresem.
Kontrakty endpointów i dalsze operacje opisują [API](api-contract.md)
oraz [obsługa PHASE 2](phase2-operations.md).

## Codzienna obsługa

Ponowne kliknięcie launchera uruchamia lub aktualizuje lokalne usługi.
W PowerShell możesz sterować nimi jawnie:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action start
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action status
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action stop
```

Zatrzymanie zachowuje `.env` i dane w nazwanych wolumenach.
Skrypty używają projektu Compose `aegis-soc`; osobny stos walidacyjny ma
własną nazwę i nie jest uruchamiany przez launcher.

`status` sprawdza publiczną gotowość i stan usług. Działanie relay i workera
potwierdza dopiero `check`, który korzysta z istniejącego administratora
i prosi o hasło w ukrytym monicie. Sprawdza logowanie, utworzenie źródła,
trwały zapis, idempotencję i dojście zdarzenia do `staged` przez relay i worker.
Po kontroli wyłącza swoje źródło, odwołuje jego tokeny i zamyka własną sesję.
Jedno syntetyczne zdarzenie, metadane wyłączonego źródła i audyt pozostają
w bazie; PHASE 2 nie ma jeszcze usuwania ani retencji tych rekordów.
Szczegółowe wyniki dotychczasowych testów zawiera [raport walidacji](validation.md).
Kontrole launchera i budowania opisuje [walidacja lokalnego startu](validation-startup.md).

Start bez monitu tworzenia konta, np. do automatyzacji:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action start -SkipAdmin
```

Ten wariant uruchamia backend bez zakładania konta. Jeżeli baza nie ma jeszcze
użytkowników, później utwórz administratora interaktywnie:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action admin
```

Kontrola bez logowania i bez tworzenia danych testowych:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action check -HealthOnly
```

Potwierdza gotowość API i zależności; pełny `check` pozostaje osobną kontrolą.

## Budowanie i przygotowanie zależności

Domyślny `-BuildMode auto` korzysta z istniejącego wheelhouse; gdy go nie ma,
próbuje online i po niepowodzeniu przechodzi do offline z dostępnym Pythonem 3.12.
Możesz wymusić pobieranie zależności podczas budowy przez `-BuildMode online`
lub użycie lokalnych wheel przez `-BuildMode offline`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\aegis.ps1 -Action start -BuildMode offline
```

Przygotowanie brakujących wheel wymaga Python 3.12 z pip oraz Internetu.
Launcher szuka dostępnego interpretera; przygotowanie można też uruchomić
ręcznie:

```powershell
py -3.12 scripts/prepare_wheelhouse.py
```

Helper zapisuje dane w ignorowanym `backend/.wheelhouse` i sprawdza hashe
z lockfile. Obraz offline instaluje tylko zweryfikowane lokalne pliki,
bez zmiany wersji zależności. Nie wyłącza weryfikacji TLS.
Pierwsze pobranie wheel i brakujących obrazów bazowych nadal wymaga sieci.

## Gdy uruchomienie się nie uda

- Jeśli Docker jest niedostępny, uruchom Docker Desktop i upewnij się, że używa
  kontenerów Linux, po czym ponów start.
- Jeśli port 8080 jest zajęty, zakończ usługę, która go używa, albo zatrzymaj
  drugi lokalny stos Aegis. Launcher korzysta z `http://localhost:8080`.
- Jeśli online build zgłasza błąd certyfikatu, użyj trybu `auto` lub przygotuj
  zależności i uruchom `offline`; dostęp do źródła pakietów nadal musi przejść
  weryfikację certyfikatu.
- Jeśli `status` zgłasza brak gotowości, sprawdź wynik startu i bezpieczne logi:

  ```powershell
  docker compose -p aegis-soc ps --all
  docker compose -p aegis-soc logs --tail 50 api relay worker
  ```

- Jeśli logowanie nie działa, użyj konta utworzonego przez `admin` i zapisanego
  hasła. Bootstrap nie resetuje istniejącego hasła.

Szczegółowe procedury awarii, limitów i ręcznego retry zawiera
[instrukcja PHASE 2](phase2-operations.md).
