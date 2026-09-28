# Backend — fundament PHASE 1

FastAPI/Pydantic/SQLAlchemy tworzą modularny monolit z oddzielnym procesem Celery.
Runtime to **Python 3.12.14**, zgodny z obrazem Docker i konfiguracją CI. Zależności
runtime i developerskie mają osobne lockfile z hashami.

Zaimplementowano konfigurację i bezpieczne błędy, `/api/v1/auth`, `/api/v1/users`,
`/api/v1/audit`, chronione `/api/v1/system/health`, sondy `/health` i `/ready`,
wewnętrzne `/metrics` oraz OpenAPI pod `/api/v1/openapi.json`.
Migracja `0001_foundation` tworzy użytkowników, sesje i audyt w PostgreSQL.
Pierwsze konto tworzy `python -m app.bootstrap`; worker udostępnia zadanie
transportowe `aegis.ping`. Przetwarzanie zdarzeń bezpieczeństwa jest kolejnym etapem.

**PHASE 1 ukończona i zweryfikowana 2026-09-28.** Przeszło 230 testów
jednostkowych oraz 33 testy integracyjne z rzeczywistymi PostgreSQL, Redis,
ClickHouse i Celery. Potwierdzono budowę obrazów Linux/Python 3.12.14, start
świeżego Compose, migracje, auth/RBAC i granty audytu. Instalacja dev lockfile
z `--require-hashes`, `pip check` oraz audyt runtime lock przeszły.
Hostowane CI pozostaje niezweryfikowane. Wyniki: [raport walidacji](../docs/validation.md).

Uruchomienie, sekrety, bootstrap i pełne komendy testów:
[instrukcja operacyjna PHASE 1](../docs/phase1-operations.md).
Zakres dalszych prac: [plan](../docs/implementation-plan.md).
Odpowiedzialność katalogów: [struktura](../docs/repository-structure.md).
