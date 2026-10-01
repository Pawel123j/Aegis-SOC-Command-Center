# Normalizacja i wyszukiwanie — obsługa PHASE 3

Zakres implementacji: sześć parserów, trwały snapshot w PostgreSQL, niezależna
projekcja ClickHouse i wyszukiwanie dla zalogowanych użytkowników SOC.
Kontrakt formatów i czasu opisuje [normalizacja](normalization.md).
Wyniki wykonanych kontroli należą do raportu walidacji.

## Uruchomienie i aktualizacja

Zwykły [launcher Windows](../Uruchom%20Aegis.cmd) zachowuje istniejące `.env`
i woluminy. Dodaje jedynie nowy, losowy `CLICKHOUSE_OWNER_PASSWORD`, jeśli
konfiguracja pochodzi z PHASE 2. Pozostałe hasła nie są zmieniane.
Przy ręcznej aktualizacji konfiguracji wykonaj:

```powershell
python scripts/bootstrap_env.py --upgrade
docker compose build api
docker compose up -d --wait
```

Dla przygotowanej lokalnej biblioteki pakietów użyj
`docker compose -f compose.yaml -f compose.offline.yaml build api`.
PostgreSQL migruje przez Alembic do `0003_normalization`; osobny
`clickhouse-migrator` stosuje numerowane SQL i sprawdza zapisane SHA-256.
Zmiana treści już zastosowanej migracji zatrzymuje aktualizację.

ClickHouse uruchamia właściciela `aegis_owner`. Migrator tworzy oddzielnego
użytkownika `aegis`, któremu nadaje wyłącznie SELECT/INSERT na tabeli zdarzeń.
Sekret właściciela jest przekazywany migratorowi i izolowanym testom;
API, worker, relay i processor nie otrzymują go. PostgreSQL nadal rozdziela
`aegis_owner` i `aegis_app`. Żaden proces runtime nie tworzy tabel.

## Etapy i odzyskiwanie

`202` oznacza trwałe przyjęcie. Relay i worker nadal kończą walidację raw
stanem `staged`. Processor (`python -m app.processor`) okresowo odnajduje
również zdarzenia przyjęte przed aktualizacją i tworzy osobne `pipeline_jobs`.

| Stan pipeline | Znaczenie |
| --- | --- |
| `pending`, `normalizing` | oczekiwanie lub próba normalizacji |
| `normalized` | niezmienny snapshot zapisany w PostgreSQL; projekcja oczekuje |
| `projecting` | próba zapisu do ClickHouse |
| `projected` | ClickHouse potwierdził zapis |
| `quarantined` | nieobsługiwany format, błędne dane lub wyczerpane próby normalizacji |
| `projection_failed` | projekcja wymaga interwencji po wyczerpaniu prób |

Snapshot i postęp normalizacji zatwierdzają się razem. Parsowanie i HTTP nie
trzymają blokady SQL. Dzierżawa i token odgradzają zapis starego procesora.
Próba jest liczona przy pobraniu zadania, również gdy proces później zginie.
Domyślnie skan odbywa się co 2 s, batch ma 25 operacji, dzierżawa trwa 60 s,
budżety wynoszą 3 próby normalizacji i 20 prób projekcji; backoff wynosi 2–60 s.

Po utracie potwierdzenia zapisu processor wysyła ten sam snapshot. Tabela
ReplacingMergeTree ma stabilny klucz zakresu i zdarzenia, a każdy odczyt stosuje
FINAL przed filtrami, zliczeniem i paginacją. Wynik nie czeka na background merge.
Wyszukiwanie jest opóźnione względem trwałego przyjęcia; niedostępność ClickHouse
nie usuwa raw ani snapshotu PostgreSQL.

Status batcha zawiera `pipeline_state`, bezpieczny kod błędu i wersję każdego
zadania. `counts.normalized` i `counts.projected` są rzeczywistymi licznikami.
`processed` pozostaje 0 do wdrożenia detekcji. Uprawnienie SYSTEM_READ daje
`GET /api/v1/system/pipeline`, z licznikami stanów i wiekiem backlogu.

Administrator może pobrać `GET /api/v1/events/{event_id}/pipeline`, a następnie
wywołać `POST /api/v1/events/{event_id}/pipeline/retry` z otrzymanym ETag
w `If-Match`. Operacja jest audytowana, wymaga aktualnej wersji i dotyczy wyłącznie
`quarantined` lub `projection_failed`. Retry projekcji zachowuje snapshot.
Retry parsera nie zmienia raw: nieobsługiwany format może ponownie trafić do
kwarantanny, dopóki adapter nie zostanie poprawiony.

## Wyszukiwanie

EVENTS_READ umożliwia `POST /api/v1/events/search`, `GET /api/v1/events`
oraz `GET /api/v1/events/{event_id}`. Token źródła służy tylko przyjmowaniu
i statusowi własnych batchy; nie otwiera wyszukiwania.

Przykładowe body wyszukiwania:

```json
{
  "from": "2026-10-01T00:00:00Z",
  "to": "2026-10-02T00:00:00Z",
  "q": "source.type = \"linux_auth\" AND event.outcome = \"failure\"",
  "mode": "live",
  "limit": 100
}
```

Zakres jest półotwarty `[from, to)`, domyślnie obejmuje ostatnie 24 h,
maksymalnie 7 dni. Obie granice muszą mieć jawny offset; lata wyszukiwania
to 1970–2299. Limit wynosi 1–500. Osobne filtry UUID to `dataset_id`, `source_id`
i `run_id`. Odpowiedź zawiera `items`, `total`, `next_cursor`, `from` i `to`.
Przy kolejnej stronie zachowaj wszystkie filtry i użyj `next_cursor` jako `cursor`.
Kursor jest podpisany, ważny 15 minut i związany z użytkownikiem oraz pełnym
zapytaniem. Projekcja nowych logów w trakcie paginacji może zmienić `total`.

Język obsługuje nawiasy, AND/OR oraz `=`, `!=`, tekstowy CONTAINS,
a dla liczb również `<`, `<=`, `>` i `>=`. AND ma pierwszeństwo przed OR.
Tekst zapisuje się w cudzysłowach JSON; `null` oznacza brak pola.
Dozwolone pola obejmują identyfikatory zakresu, `source.*`, `destination.*`,
`user.id/name/realm`, `user.target.id/name/realm`, `host.id/name`,
`process.name/executable/command_line`, `event.category/type/action/outcome/severity/code`,
`network.protocol` i `http.status_code`. W Windows konto logowania jest
w `user.target`; `user` wskazuje podmiot wykonujący operację.
Aliasy obejmują `username`, `hostname`, `source_ip`, `destination_ip`,
`source_port`, `destination_port`, `process_name`, `command_line`, `action`,
`source_type`, `severity` i `result`. Wynik `failed` jest aliasem `failure`.
IP są porównywane po kanonizacji IPv4/IPv6, także dla adresów IPv4 mapped IPv6.

Nie ma dowolnego SQL, funkcji, regex ani wildcardów. Maksimum to 4096 znaków,
64 porównania, 256 tokenów i 12 poziomów nawiasów. Zapytania korzystają
z parametrów HTTP ClickHouse i stałej allowlisty kolumn. Limity wykonania:
3 s, milion odczytanych wierszy, 256 MiB pamięci/odczytu i 50 MiB odpowiedzi.
Przekroczenie limitów lub awaria archiwum zwraca redagowane `503`;
błędny filtr, czas lub kursor zwraca `422`.

## Kontrola i retencja

`scripts/aegis.ps1 -Action check` sprawdza login, idempotencję, raw → normalized
→ projected i odczyt własnego syntetycznego zdarzenia z archiwum. Po kontroli
wyłącza własne źródło i zamyka własną sesję; historia zdarzenia i audytu pozostaje.
Samo `-HealthOnly` potwierdza jedynie sondy zależności.

Automatyczna retencja nadal nie jest wdrożona. Limity PHASE 2 dotyczą liczby
zachowanych raw, ich bajtów i pozycji potwierdzeń; nie mierzą fizycznego rozmiaru
PostgreSQL ani dodatkowych snapshotów/projekcji. Ukończone i błędne zdarzenia
wciąż zajmują pojemność. Nie używaj `down --volumes`, prune ani ręcznego kasowania
rekordów jako procedury aktualizacji istniejącej aplikacji. Retencja wymaga
oddzielnej polityki checkpointów i dowodów w dalszych fazach.
