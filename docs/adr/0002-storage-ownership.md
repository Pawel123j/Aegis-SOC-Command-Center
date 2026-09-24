# ADR 0002 — rozdzielenie stanu i archiwum

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

## Kontekst

Praca analityka wymaga transakcji i historii zmian. Event Explorer wymaga skanowania
dużych zbiorów. Dwóch magazynów nie można traktować jako jednej transakcyjnej bazy.

## Decyzja

PostgreSQL jest źródłem prawdy dla konfiguracji, identity, inbox/outbox, stanu
detekcji, alertów i spraw. ClickHouse jest archiwum eventów i odbudowywalną projekcją
adnotacji. Evidence użyte w alertach jest kopiowane do trwałego snapshotu PostgreSQL.
Proces detekcji nie czeka na analityczną projekcję. Redis nie przechowuje jedynego
egzemplarza stanu operacyjnego. Dedupe ClickHouse jest jawne także na odczycie.

Alembic zarządza PostgreSQL; ClickHouse ma osobne numerowane migracje SQL z checksum.
Osobna rola migratora ma DDL, role API/worker nie. Retencja i checkpointy decydują
o bezpiecznym usunięciu inbox; samo opublikowanie do kolejki nie wystarcza.

## Alternatywy i konsekwencje

- Sam PostgreSQL wystarczyłby dla małego demo i zmniejszył koszt utrzymania, ale
  nie pokazałby rozdzielenia analityki wolumetrycznej od transakcji SOC.
- Sam ClickHouse utrudniałby transakcyjne relacje case i uprawnienia operacyjne.
- Bezpośredni dual-write API do obu baz tworzyłby nierozwiązaną lukę awaryjną.

Kosztem wyboru są opóźniona spójność wyszukiwania, dwa systemy migracji/backupów
i konieczność pomiaru lag. Zysk ClickHouse trzeba potwierdzić benchmarkiem; nie
dodajemy trzeciego silnika wyszukiwania bez konkretnego wymagania.

## Dowód i ponowna ocena

Test outage ClickHouse: przyjęte logi pozostają trwałe, alert ma evidence, projection
dogania po restarcie, ponowienia nie zmieniają liczników wyszukiwania. Rewizja ADR,
jeśli koszt dwóch magazynów przewyższy mierzalne korzyści lub inbox stanie się wąskim gardłem.
