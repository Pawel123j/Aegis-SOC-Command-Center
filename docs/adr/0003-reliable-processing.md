# ADR 0003 — trwałe przetwarzanie i retry

Status: przyjęta w PHASE 0, wdrożona dla raw ingestion w PHASE 2 (2026-09-30).
Efekty detekcji, incydentów i SOAR pozostają projektem przyszłych faz.

## Kontekst

Commit w PostgreSQL i publikacja w Redis mogą rozdzielić się przez awarię. Worker
może umrzeć po zapisie alertu przed ACK. Redis może utracić transportowe wiadomości.

## Decyzja

Trwały inbox i outbox w jednej transakcji przyjęcia. Celery/Redis dostarcza pracę
co najmniej raz; sweeper PostgreSQL odzyskuje nieukończone zadania. Payload Celery
to identyfikator, JSON serializer, bez pickle. Transakcje efektów obejmują checkpoint,
klucz idempotencji, alert/case i outbox. Lease ma fencing token; stary worker nie
może zatwierdzić efektu po utracie lease. Retry ma limit i trwałą kwarantannę błędów.

Warunek sukcesu nie zależy od obietnicy „exactly once” transportu. Źródło kontroluje
batch idempotency key i stabilny source_event_id, serwer sprawdza konflikty body.
Ustawienia transportu nie zastępują trwałego rejestru PostgreSQL.

## Implementacja PHASE 2

`ingestion_batches`, `raw_events`, `batch_events`, `outbox_jobs`, liczniki
`ingest_capacity` i `events.accepted` powstają przed `202` w jednej transakcji.
API nie wywołuje brokera. Wiersz capacity serializuje admission i sprawdzenie
pending limit przy retry. Osobne limity obejmują zachowane eventy, bajty envelope,
pozycje potwierdzeń oraz liczbę i wiek nieukończonych zadań.

Relay (`python -m app.relay`) pobiera do 50 gotowych zadań przez `FOR UPDATE
SKIP LOCKED`, zatwierdza token i dzierżawę, a następnie publikuje tylko UUID eventu
i generation. Nie trzyma transakcji podczas I/O brokera. Wynik publikacji zapisuje
wyłącznie przy zgodnym tokenie i generacji. Liczy próbę już przy claim, więc crash
przed publikacją również zużywa skończony budżet. Sukces publikacji nie kończy
zadania: następny skan po 30 s może odtworzyć utraconą wiadomość Redis.

Worker zatwierdza własny claim, sprawdza hash/rozmiar/envelope poza transakcją
i warunkowo kończy zadanie przez generation + worker_token. Wygasłą dzierżawę
można przejąć. Ukończone zadanie ignoruje duplikaty dostarczenia, a stara generacja
nie może zakończyć nowej pracy. Faza kończy się stanem `staged`, czyli gotowością
do normalizacji, albo `quarantined`; nie tworzy alertu ani normalized eventu.

Domyślne ustawienia: dzierżawa dispatch 30 s, worker 60 s, Celery soft/hard
20/30 s, visibility timeout 120 s, acks_late i reject_on_worker_lost. Retry
jest sterowany stanem PostgreSQL, z opóźnieniem 2–60 s, maksymalnie 10 prób
dispatch i 5 prób processing na generację. Stały błąd danych trafia od razu
do kwarantanny. Admin może audytowanym retry zwiększyć generację przy zgodnym
If-Match i dostępnej pojemności pending; surowy payload pozostaje niezmienny.

Brak automatycznej retencji jest świadomą granicą PHASE 2. Staged i quarantine
wciąż zajmują pojemność. Przy długiej awarii budżet może zakończyć się kwarantanną,
co wymaga działania operatora zamiast obietnicy nieskończonego retry.
[Instrukcja operacyjna](../phase2-operations.md) opisuje statusy i odzyskiwanie.

## Alternatywy i konsekwencje

FastAPI BackgroundTasks bez trwałego rejestru traci pracę przy restarcie.
Kafka wprowadza dodatkową infrastrukturę bez usunięcia potrzeby idempotencji efektów.
RQ byłoby wystarczające dla prostych zadań; Celery wybieramy dla routingu kolejek,
retry i ekosystemu, ale ledger workflow SOAR pozostaje naszą domeną w PostgreSQL.

Koszt: dodatkowe tabele i sweeper. Początkowe blokady serializujące niewielkie
operacje preferują poprawność nad maksymalnym EPS. Redis awaria może ograniczyć
auth/rate limit i odbiór pracy; API nie obniża wtedy po cichu zabezpieczeń.

## Dowód i ponowna ocena

Zakres testów PHASE 2 obejmuje atomowy rollback admission/audit, duplikaty,
crash przed/po publikacji, utratę wiadomości, dzierżawy, spóźnione wyniki,
ograniczenia prób, manualny retry i rzeczywisty transport Celery/Redis.
Wyniki wykonania są w [raporcie walidacji](../validation.md). Scenariusze
deterministycznych awarii przez SystemExit nie są testem OS-kill; osobny test
transportowy zatrzymuje i uruchamia worker in-process z izolowaną kolejką.
Przyszłe efekty detekcji/SOAR wymagają własnego dowodu atomowości i idempotencji.
Kolejny broker rozważamy dopiero po pomiarze
przepustowości i analitycznym wykazaniu, którego ograniczenia nie rozwiązuje obecny model.
