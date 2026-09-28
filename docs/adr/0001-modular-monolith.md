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

### Doprecyzowanie runtime w PHASE 1 — 2026-09-26

Backend używa **Python 3.12.14** zamiast 3.13 wskazanego w początkowym README.
Dostępne lokalne środowisko 3.12.14 zostało sprawdzone przez instalację zależności
z hashami, `pip check` oraz 211 testów jednostkowych. Ten sam patch version
przypięto w `backend/Dockerfile` i `.github/workflows/backend.yml`; metadane
pakietu dopuszczają `>=3.12,<3.13`. Spójność interpretera i zależności między
lokalną walidacją, kontenerem i CI ułatwia odtwarzanie błędów. Nie deklarujemy
niezgodności aplikacji z Python 3.13 — ta wersja nie przeszła obecnej walidacji.

Lockfile runtime i dev mają piny i hashe. Dev zawiera `httpx2`, wymagany przez
TestClient użytej wersji Starlette; nie wyłączamy ostrzeżeń, aby ukryć niezgodność.
To doprecyzowanie narzędzi istniejącej decyzji o monolicie, bez zmiany granic
modułów. Na dzień 2026-09-26 integracja pozostawała otwartą bramką PHASE 1.

Aktualizacja 2026-09-28: bramka została zamknięta. Obrazy API i testów z Python
3.12.14 zbudowano, świeży Compose z migracjami uruchomiono, a integracja
z PostgreSQL, Redis, ClickHouse i Celery dała 33 passing tests. Lokalny zestaw
jednostkowy obejmuje teraz 230 passing tests. Hostowane CI nadal nie było
uruchamiane; dokładne dowody zawiera [raport walidacji](../validation.md).

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
Zmiana minor Pythona wymaga ponownego rozwiązania zależności, kontroli ich hashy
oraz testów jednostkowych i integracyjnych na tej samej wersji lokalnie, w obrazie
i w CI. Udane testy na jednym systemie nie zastępują pozostałych bramek.
