# ADR 0001 — modularny monolit

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

## Kontekst

Platforma ma wiele domen, ale jednego autora, wspólny cykl wdrożenia i lokalne demo.
Mikroserwisy wprowadziłyby kontrakty sieciowe i spójność rozproszoną przed uzyskaniem
działającej detekcji. Jednocześnie długie przetwarzanie nie może blokować API.

## Decyzja

Python/FastAPI/Pydantic/SQLAlchemy w jednym backendzie. Oddzielne procesy API,
Celery worker i scheduler/relay używają tej samej wersji kodu. Moduły domenowe mają
usługi, jawne DTO/ports i testy; zewnętrzne I/O pozostaje w adapterach. Czyste
funkcje detekcji, korelacji i ryzyka są uruchamiane także przez test/replay.

## Alternatywy i konsekwencje

- Mikroserwisy: lepsza niezależność wdrożeń przy wielu zespołach, wyższy koszt tutaj.
- Wszystko w HTTP request: prostszy start, brak kontrolowanego retry i backpressure.
- Jeden wielki moduł: szybki prototyp, trudne testy i rozmyta odpowiedzialność.

Wybrane rozwiązanie ogranicza liczbę deploymentów, ale wymaga egzekwowania granic
modułów. Wspólna baza nie daje zgody na dowolny zapis do cudzych tabel.

## Dowód i ponowna ocena

PHASE 1: API i worker uruchamialne niezależnie; domena nie importuje transportu.
PHASE 4: evaluator uruchamialny bez FastAPI/Redis. Nowy ADR o wydzieleniu usługi
dopiero przy zmierzonym problemie skalowania lub niezależnym cyklu wdrożeń.
