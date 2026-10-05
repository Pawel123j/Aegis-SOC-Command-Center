# Infrastruktura — lokalny deployment

Przeznaczenie: migracje ClickHouse, reverse proxy i konfiguracja obserwowalności.
Compose uruchamia PostgreSQL, Redis, ClickHouse, migratory, API, relay, worker,
processor, detector, correlator oraz lokalny reverse proxy na 127.0.0.1:8080.
Correlator Etapu 2 używa tego samego obrazu i sieci backend; nie wymaga
nowej bazy ani otwartego portu. `compose.offline.yaml` umożliwia build
z lokalnych, zweryfikowanych zależności.
Risk Engine Etapu 3 działa w procesach API/detector/correlator, korzysta
z migracji PostgreSQL i nie dodaje portu ani nowego kontenera.
MITRE Etapu 4 używa tych samych procesów i lokalnego katalogu w obrazie.
Migracja `0008_mitre` dodaje append-only snapshoty i indeksy agregacji;
role runtime zachowują wyłącznie SELECT/INSERT do historii mapowań.
[Walidacja Etapu 4](../docs/validation-mitre.md).
Sigma Etapu 5 dodaje `0009_sigma` bez nowego portu lub procesu. Definicje
są append-only; kontrolowana funkcja wybiera utrwaloną rewizję w deployment.
Nie przyznaje runtime ogólnych uprawnień zmiany wersji reguł.
[Walidacja Etapu 5](../docs/validation-sigma.md).
Profile encji Etapu 6 działają w istniejących procesach API/processor/detector/
correlator i korzystają z PostgreSQL. Migracja `0010_entities` jest bieżącym
head wymaganym przez readiness; dodaje pięć append-only tabel z grantami
SELECT/INSERT dla runtime, kontrolą kompletności receipts i odmową niepustego
downgrade. Osiem metod `/api/v1/entities` (siedem GET i jeden POST backfill)
korzysta z istniejącego proxy. Profile nie dodają kontenera, portu ani zależności.
Ryzyko jest projekcją najwyższej kwalifikującej się istniejącej oceny alertu,
bez nowego obliczenia encji. Implementacja jest gotowa; końcową regresję
i uruchomienie Etapu 6 opisuje raport wraz z granicami dowodu.
[Kontrakt profili](../docs/entities.md),
[stan walidacji Etapu 6](../docs/validation-entities.md).
PostgreSQL migruje oddzielny Alembic w backend/migrations, role runtime nie mają DDL.
[Granice infrastruktury](../docs/architecture.md).
[Uruchomienie](../docs/local-start.md), [walidacja korelacji](../docs/validation-correlation.md).
