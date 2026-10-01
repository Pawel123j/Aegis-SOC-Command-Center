# Infrastruktura — lokalny deployment

Przeznaczenie: migracje ClickHouse, reverse proxy i konfiguracja obserwowalności.
Compose uruchamia PostgreSQL, Redis, ClickHouse, migratory, API, relay, worker,
processor, detector, correlator oraz lokalny reverse proxy na 127.0.0.1:8080.
Correlator Etapu 2 używa tego samego obrazu i sieci backend; nie wymaga
nowej bazy ani otwartego portu. `compose.offline.yaml` umożliwia build
z lokalnych, zweryfikowanych zależności.
PostgreSQL migruje oddzielny Alembic w backend/migrations, role runtime nie mają DDL.
[Granice infrastruktury](../docs/architecture.md).
[Uruchomienie](../docs/local-start.md), [walidacja korelacji](../docs/validation-correlation.md).
