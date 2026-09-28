# Observability i metryki SOC

Status: projekt docelowy z ukończonym fundamentem PHASE 1 (2026-09-28).
Sondy, metryki HTTP i logi JSON przeszły testy jednostkowe i integrację; przez
proxy `/health` i `/ready` zwracają 200, a wewnętrzne `/metrics` pozostaje
niedostępne z zewnątrz (404). Osobno potwierdzono zadanie Celery przez rzeczywisty
broker, worker i result backend. Dowody: [raport walidacji](validation.md).
Instrumentacja kolejnych modułów, dashboard operacyjny i benchmark należą
do przyszłych faz. Poniższe wskaźniki domenowe nie są wynikami pomiarów.

## Health i logi

`/health`: żyje proces. `/ready`: aplikacja ma zgodny schemat i wymagane połączenia;
brak PostgreSQL/Redis/ClickHouse daje 503 dla pełnej gotowości. Nie oznacza to utraty
przyjętych eventów: status komponentów rozróżnia przechowanie, przetwarzanie i indeksowanie.
Worker heartbeat, lag inbox/outbox i wiek watermark są oddzielnymi wskaźnikami;
żywy proces API nie dowodzi pracy detekcji.

JSON logs: timestamp, level, service, operation, request_id, trace/correlation_id,
batch/run ID, stage, duration_ms, result/error_code. Nie logujemy body auth,
tokenów, surowych eventów ani command line przez domyślny logger. Nie ufamy
request_id bez walidacji długości/znaków; nowy ID jest bezpieczną wartością zastępczą.
Audyt to trwały rekord domenowy w PostgreSQL, odrębny od stdout logów diagnostycznych.

## Metryki techniczne

| Nazwa projektowa | Znaczenie |
| --- | --- |
| `aegis_events_accepted_total` | Trwale przyjęte logiczne eventy, retry bez przyrostu |
| `aegis_events_processed_total` | Ukończone logiczne etapy, etykieta stage/outcome |
| `aegis_events_failed_total` | Trwałe błędy i kwarantanna; oddzielone od retry attempts |
| `aegis_alerts_generated_total` | Nowe logiczne alerty, rewizja nie jest nowym alertem |
| `aegis_processing_duration_seconds` | Histogram czasu pracy etapu |
| `aegis_end_to_end_latency_seconds` | Od received_at do alert.created_at; zawiera backlog i finalizację |
| `aegis_ingest_backlog`, `aegis_outbox_oldest_age_seconds` | Rozmiar i wiek nieukończonej pracy |
| `aegis_detection_watermark_lag_seconds` | Różnica serwerowego czasu i zamkniętego watermark |
| `aegis_projection_lag_seconds` | Opóźnienie widoczności w ClickHouse |
| `aegis_playbook_executions_total` | Trwałe run wg outcome, osobno step attempts |

Prometheus multiprocess counters są obserwacją procesu i mogą mieć luki przy crash;
audytowalne liczniki dashboardu liczymy z trwałych rekordów PostgreSQL/ClickHouse.
Nie obiecujemy dokładnie jednego przyrostu eksportera przy atomowym commicie bazy.
Nie używamy user/IP/event/run ID jako labels; nieograniczona cardinality wyczerpałaby
pamięć. Dopuszczalne labels to service, stage, outcome i skończony tryb live/replay.

## Metryki domenowe

Wspólna kohorta: live, stały zakres UTC `[from,to)`, wykluczone replay/demo,
jawny count i pokrycie danych. Puste mianowniki dają null / „brak danych”.

| Metryka | Definicja |
| --- | --- |
| MTTD | Średnia alert.created_at minus najwcześniejszy timestamp contributing event, alerty utworzone w zakresie |
| MTTA | Średnia first_acknowledged_at minus incident.created_at, dla incydentów utworzonych w zakresie z pierwszym Triaged |
| MTTR | Średnia first_resolved_at minus incident.created_at, dla incydentów utworzonych w zakresie z Resolved |
| False Positive Rate | Liczba spraw zakończonych False Positive / liczba spraw zakończonych (False Positive lub Resolved) w zakresie czasu zamknięcia; licznik i mianownik jawne |
| Alerts / incidents per day | Nowe logiczne rekordy per doba UTC; merge aliases nie są nowymi incydentami |
| Top rules | Alerty per rule ID/version, bez liczenia evidence revisions |
| Noisy rules | Wolumen alertów i liczba powiązanych spraw FP per unikalne rule-case pair; to nie jest FPR samej reguły, niesklasyfikowane osobno |
| EPS | Ukończone unikalne eventy w ostatnich 60 s / 60, ze wskazanym oknem |

MTTD jest przybliżeniem opartym na obserwowanych logach, nie czasem od rzeczywistego
początku włamania. Dodatkowo pokazujemy czas od kotwicy detekcji, aby oddzielić
pięciominutowe zbieranie prób od opóźnienia pipeline. Niewiarygodne zegary są wykluczone
z MTTD z jawną liczbą wykluczeń. Reopen nie usuwa first_*; UI pokazuje także latest
resolution i reopen count. Czas do False Positive nie jest MTTR naprawy.

Overview: alerty/24 h, aktywne i critical cases, EPS, top rules/IP/accounts, severity
oraz MITRE distribution. Agregaty MITRE zliczają alert-technique pairs; suma może
przewyższać liczbę alertów, co musi wyjaśniać legenda. Filtr scope dotyczy wszystkich
kafli jednocześnie. Raport incydentu zapisuje wersję/snapshot i zakres czasu.

## Walidacja i cele

Fixtures z jawnie ustawionymi timestampami sprawdzają średnie, puste kohorty,
reopen, FP, duplikaty, częściowo rozstrzygnięte sprawy oraz rozdzielenie live/replay.
Test outage zatrzymuje worker/Redis/ClickHouse i sprawdza, czy Health pokazuje
konkretną degradację zamiast samego HTTP 200. Test logów szuka ujawnienia sekretów.

Projektowe cele startowe: p95 ingest acceptance <500 ms przy 100 EPS; online alert
do 120 s bufora + 10 s pracy/backlog w tym obciążeniu; p95 query 24 h <2 s dla
1 mln eventów. Obciążenie, sprzęt, rozmiary logów i cache raportujemy razem z wynikiem.
Brak wykonania benchmarku oznacza „niezmierzone”, nigdy „SLO spełnione”.
