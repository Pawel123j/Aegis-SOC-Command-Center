# ADR 0003 — trwałe przetwarzanie i retry

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

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
Celery ACK/worker-loss/visibility timeout będą dobrane razem z timeouts zadań,
a następnie sprawdzone testem awarii: [Redis transport](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html).

## Alternatywy i konsekwencje

FastAPI BackgroundTasks bez trwałego rejestru traci pracę przy restarcie.
Kafka wprowadza dodatkową infrastrukturę bez usunięcia potrzeby idempotencji efektów.
RQ byłoby wystarczające dla prostych zadań; Celery wybieramy dla routingu kolejek,
retry i ekosystemu, ale ledger workflow SOAR pozostaje naszą domeną w PostgreSQL.

Koszt: dodatkowe tabele i sweeper. Początkowe blokady serializujące niewielkie
operacje preferują poprawność nad maksymalnym EPS. Redis awaria może ograniczyć
auth/rate limit i odbiór pracy; API nie obniża wtedy po cichu zabezpieczeń.

## Dowód i ponowna ocena

Testy crash przed/po enqueue, przed/po commit, utraty Redis i równoległych workerów
muszą zachować jeden efekt biznesowy. Kolejny broker rozważamy dopiero po pomiarze
przepustowości i analitycznym wykazaniu, którego ograniczenia nie rozwiązuje obecny model.
