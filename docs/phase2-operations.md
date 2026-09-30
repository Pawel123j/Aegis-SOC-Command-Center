# PHASE 2 — obsługa trwałego ingestion

Stan implementacji: 2026-09-30. Wyniki wykonanych kontroli są w
[raporcie walidacji](validation.md); poniżej opisano kontrakt i procedury.

API przyjmuje dane do PostgreSQL, relay publikuje identyfikatory do Redis,
a worker sprawdza integralność i przygotowuje rekord do normalizacji.
`202` oznacza zatwierdzony zapis, a `staged` gotowość do następnej fazy.
PHASE 2 nie tworzy normalized events, alertów, incydentów ani projekcji ClickHouse.
Nie udostępnia wyszukiwania ani replay. Publiczne źródła pracują wyłącznie w `live`.

## Uruchomienie i obserwacja

Użyj przygotowanej konfiguracji lokalnej opisanej w [README](../README.md).
Migrator doprowadza schemat do `0002_ingestion`; oddzielne usługi `api`, `relay`
i `worker` muszą używać tej samej bazy i ustawień ingestion. Domyślna kolejka to
`ingestion`; worker Compose obsługuje również `celery` dla technicznego ping.

```powershell
docker compose config --quiet
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail 50 relay worker
```

Odtworzenie kontenera API może zmienić jego adres IP przy zachowaniu nazwy `api`,
zgodnie z [modelem sieci Compose](https://docs.docker.com/compose/how-tos/networking/#updating-containers-on-the-network).
Proxy korzysta z DNS Dockera `127.0.0.11`, cache `valid=5s` i
[`resolve` we współdzielonym upstream](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#resolve).
Odświeża adres automatycznie, bez restartu proxy. Podczas wymiany API lub
oczekiwania na jego gotowość mogą wystąpić przejściowe `502`, `503` lub timeout;
5 s ważności DNS nie jest gwarancją maksymalnej długości przerwy.

Po aktualizacji sprawdź stan usług oraz `/health` i `/ready` przez proxy:

```powershell
docker compose ps --all
curl.exe --fail http://localhost:8080/health
curl.exe --fail http://localhost:8080/ready
```

Oczekuj `200` z obu sond. Jeśli błędy utrzymują się po uruchomieniu API,
sprawdź jego gotowość, sieć usług i konfigurację proxy przez
`docker compose exec proxy nginx -t`.

`/ready` sprawdza bazę, rewizję migracji, Redis i ClickHouse. Nie dowodzi, że
relay/worker faktycznie przetwarza zadania. Potwierdzeniem jest zmiana statusu
przyjętego batcha i brak narastania wieku zadań. Admin lub Manager odczytuje
`GET /api/v1/system/ingestion` ze swoim JWT; odpowiedź zawiera liczniki unikalnych
eventów, pozycji potwierdzeń, bajtów payloadu, cztery stany i aktualne limity.

## Źródło i jednorazowy credential

Admin tworzy źródło przez `POST /api/v1/sources`, np. body:

```json
{"name":"local-json-feed","source_types":["generic_json"],"timezone":"UTC"}
```

`201` zawiera `source` oraz `credential`; `credential.token` jest dostępny tylko
w tej odpowiedzi. Zachowaj go w magazynie sekretów nadawcy. Endpointy odczytu
zwracają metadane, bez tokena i jego hasha. Początkowy credential ma oba scopes
`events:write` i `events:status`, ważność 30 dni. Dodatkowy credential tworzy
`POST /api/v1/sources/{source_id}/credentials` z `scopes` i `expires_in_days`
od 1 do 90. API nie wymienia credentiali automatycznie.

Konfiguracja `source_types` dopuszcza `generic_json`, `linux_auth`, `windows_auth`,
`windows_process`, `firewall` i `nginx`. Jest to lista dozwolonych typów wejścia;
parsery normalizujące należą do PHASE 3. API generuje `source_id`, osobny
`dataset_id`, `mode=live` i zerowy UUID `run_id`. Nadawca nie podaje tych pól.

Rotacja: wydaj nowy credential, przełącz nadawcę, a następnie odwołaj poprzedni
przez `DELETE /api/v1/sources/{source_id}/credentials/{credential_id}`.
Odpowiedź `204` oznacza odwołanie, nie usunięcie historii. Wyłączenie źródła
przez `PATCH /api/v1/sources/{id}` z `{"enabled":false}` wymaga `If-Match`
aktualnej wersji i odwołuje wszystkie jego credentiale. Ponowne włączenie źródła
nie przywraca starych tokenów: Admin musi wydać nowy. Wyłączenie blokuje nowe
przyjęcia i odczyt źródłowym tokenem; już przyjęte eventy pozostają do przetworzenia.

## Wysłanie i potwierdzenie

Przykład HTTP pokazuje miejsca na wartości uzyskane w poprzednich krokach;
nie zawiera działającego sekretu:

```http
POST /api/v1/events
Authorization: Bearer <source-credential>
Idempotency-Key: collector-batch-0001
Content-Type: application/json

{"events":[{"source_type":"generic_json","source_event_id":"log-0001","timestamp":"2026-09-30T12:00:00Z","raw_event":{"action":"login","result":"failed","source_ip":"192.0.2.10"}}]}
```

Body może też być pojedynczym envelope bez `events`. Idempotency key jest
obowiązkowy, ma 1–128 znaków `[A-Za-z0-9._:-]`. Przechowuj go do potwierdzenia
żądania; po timeout ponów to samo wejście z tym samym kluczem. Taki sam scope,
klucz i kanoniczna treść zwracają poprzedni batch oraz jego `request_id`.
Zmiana treści przy tym samym kluczu daje `409 idempotency_conflict`.

`source_event_id` jest opcjonalny. Ten sam identyfikator z tą samą treścią w
obrębie source/dataset/mode/run korzysta z istniejącego eventu, również w innym
batchu. Inna treść daje `409 event_id_conflict` dla całego żądania. Bez tego pola
dwa identyczne rekordy są osobnymi eventami; sama zgodność raw nie jest deduplikacją.
Kolejność rekordów ma znaczenie. Obiekt JSON jest kanonizowany, więc różna
kolejność kluczy i równoważne liczby JSON nie tworzą nowych wersji treści.

`202` zawiera `batch_id`, `accepted_count`, `created_count`, `duplicate_count`,
`status_url`, `request_id` oraz nagłówek `Location`. Liczniki dotyczą pozycji
wejściowych: accepted = created + duplicate. W statusie `records` zachowuje
pozycje od 0; powtórzone ID mogą wskazywać ten sam `event_id`.

Odczytaj `status_url` z credentialem `events:status` tego źródła albo ludzkim
JWT z `events:read` (wszystkie cztery role). Status nie zwraca raw treści.
Źródłowy credential dla innego batcha dostaje `404`.

| Stan | Znaczenie |
| --- | --- |
| `pending` | Trwale zapisany; czeka na dostarczenie lub ponowną próbę |
| `processing` | Worker posiada dzierżawę; przerwana praca może zostać odzyskana |
| `staged` | Integralność i podstawowy kształt sprawdzone; gotowy do PHASE 3 |
| `quarantined` | Trwały błąd danych lub wyczerpane próby; raw nadal zachowany |

Wartości `normalized`, `processed`, `projected` w statusie PHASE 2 wynoszą zero.
Pusty tekst trafia do kwarantanny `empty_payload`; tekst typu `generic_json`
musi parsować się jako obiekt JSON, inaczej otrzymuje `invalid_json`. Inne typy
przechodzą kontrolę integralności i envelope bez parsowania ich treści domenowej.

## Limity i pojemność

| Kontrola | Wartość domyślna / zachowanie |
| --- | --- |
| Batch | 1–500 pozycji; niepoprawny envelope odrzuca całość `422` |
| HTTP body | 1 MiB dla ingest; przekroczenie `413` |
| `raw_event` | 64 KiB UTF-8 tekstu lub kanonicznego obiektu JSON; głębokość 16 |
| Format | Nieskompresowany JSON, bez zduplikowanych kluczy, NaN/Infinity i wadliwego UTF-8 |
| Tempo źródła | 10 żądań w oknie 1 s, wspólnie dla wszystkich jego credentiali; `429` z `Retry-After` |
| Zachowane eventy | `ingest_max_stored_events`: 100 000 |
| Pozycje potwierdzeń | `ingest_max_receipt_records`: 200 000, również batch z samymi duplikatami |
| Bajty envelope | `ingest_max_stored_bytes`: 536 870 912 (512 MiB) |
| Oczekujące zadania | `ingest_max_pending_events`: 10 000, suma pending + processing |
| Wiek najstarszego oczekującego | `ingest_max_oldest_pending_seconds`: 300 s, według `created_at` zadania |

Limity pojemności są globalne dla instancji. Bajty oznaczają sumę kanonicznych
envelope, nie fizyczny rozmiar bazy, indeksów, WAL lub audytu. Liczniki zachowanych
danych obejmują też staged i quarantined. Zbyt duży nowy zapis daje
`503 ingest_backpressure` z `Retry-After: 5`. Nowy batch zawierający wyłącznie
duplikaty zużywa limit potwierdzeń, lecz nie dodaje nowych eventów do backlogu.
Ponowienie istniejącego batcha z tym samym kluczem nie zużywa dodatkowej pojemności;
nadal wymaga autoryzacji i przejścia limitera. Niedostępny Redis limiter daje
`503 limiter_unavailable` przed przyjęciem danych.

Ustawienia mają prefiks środowiska `AEGIS_` i nazwę uppercase, np.
`AEGIS_INGEST_MAX_PENDING_EVENTS`. Compose nie przekazuje dowolnych zmiennych
hosta ani wpisów `.env` automatycznie. Zmianę dodaj w jawnym Compose override
`environment` dla `api`, `relay` i `worker`, a następnie odtwórz te usługi.
Zmiana kolejki wymaga także zgodnego argumentu `--queues` workera.
Wartości startowe nie są deklaracją zmierzonej przepustowości EPS.

## Awaria, odzyskiwanie i ręczny retry

Relay skanuje PostgreSQL co 2 s, maksymalnie 50 zadań na turę. Dzierżawa publikacji
trwa 30 s; udana publikacja pozostawia zadanie do ponownego skanu po 30 s do czasu
stanu terminalnego. To umożliwia odzyskanie utraconej wiadomości Redis. Worker
ma dzierżawę 60 s, Celery limity soft/hard 20/30 s oraz visibility timeout 120 s.
Retry stosuje opóźnienie 2–60 s. Budżet wynosi 10 prób publikacji i 5 prób
przetwarzania na generację; próba publikacji jest liczona już przy zajęciu zadania.
Przy długiej awarii rekord przechodzi do kwarantanny zamiast krążyć bez końca.

1. Sprawdź `/ready`, stan usług, status batcha i chroniony widok pojemności.
2. Przywróć niedostępną usługę. PostgreSQL zachowuje przyjęte raw, membership
   i zadanie; wygasłe dzierżawy umożliwiają wznowienie. Transport jest at-least-once.
3. Przy kwarantannie rozróżnij błąd danych od `dispatch_exhausted` lub
   `processing_exhausted`. API pokazuje bezpieczny `error_code`, bez wyjątku sterownika.
4. Po usunięciu przyczyny Admin wywołuje `POST /api/v1/events/{event_id}/retry`
   z `If-Match: "<generation>"` odczytanym ze statusu. Brak wersji daje `428`,
   stara wersja `412`, stan inny niż quarantined `409`. Zapełniony backlog daje
   `503 ingest_backpressure`; retry nie omija limitu pending.
5. `200` zwraca nową generację i `pending`, resetuje próby i dzierżawy oraz zapisuje
   audyt w tej samej transakcji. Sprawdź dalszy status. Retry nie poprawia raw;
   uszkodzony lub pusty payload ponownie trafi do kwarantanny.

Nie ma automatycznej retencji, TTL surowych rekordów ani endpointu ich usuwania.
Limit zachowanych danych nie zwalnia się po staged. Osiągnięcie tego limitu wymaga
zaplanowania archiwizacji/retencji w kolejnej fazie lub uzasadnionej zmiany limitu
po sprawdzeniu zasobów. Restart i ręczny retry nie zwalniają miejsca. Downgrade
migracji usuwa tabele PHASE 2 i nie jest procedurą naprawy działającej instancji.

Algorytm transakcji i fencing opisuje [ADR 0003](adr/0003-reliable-processing.md).
