# Struktura repozytorium

Status: układ docelowy z PHASE 0. Fundament backendu, testy i infrastruktura PHASE 1
są ukończone i zweryfikowane w Compose (2026-09-28); wyniki zawiera
[raport walidacji](validation.md). Katalogi przyszłych modułów zachowują `.gitkeep`.
Moduł `ingestion`, API `sources/events`, proces `relay`, migracja `0002_ingestion`
i testy przyjęcia zdarzeń powstały w PHASE 2. Przyszłe moduły
nie zawierają pustych funkcji lub fałszywych endpointów. Poniżej ścieżki istniejącego
szkieletu i odpowiedzialności planowanego kodu.

Aktualizacja 2026-10-06: działający kod obejmuje także PHASE 3 i Etapy 1–8
nowego planu. `entities` zawiera rzeczywistą politykę tożsamości, indeks,
modele i zapytania, a `frontend/src/entities` widoki profili.
Etap 7 dodaje rzeczywisty moduł `intelligence`: normalizację, ekstrakcję,
modele/rewizje, lokalnego providera i ledger dopasowań; panel jest w
`frontend/src/intelligence`. `risk/engine_v4.py` rozwija kontekst IOC,
zachowując `engine.py` jako v3 fallback. Head nowych źródeł to
`0011_intelligence`; [raport Etapu 7](validation-intelligence.md) potwierdza
regresję i lokalne uruchomienie, z opisanymi granicami dowodu.
Etap 8 dodaje `backend/app/modules/attack_timeline`, osobny router oraz
`frontend/src/incidents/AttackTimeline.tsx` i hook chronologii. Korzysta
z istniejącego indeksu, bez migracji; [nowy raport](validation-attack-timeline.md)
zapisuje kontrole tego przyrostu. Stan na 2026-10-06: implementacja Etapu 8
jest gotowa, a pełna regresja i lokalne wdrożenie zakończyły się poprawnie.

```text
.
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI routers, dependencies, DTO transportu
│   │   ├── core/                # konfiguracja, security primitives, logging
│   │   ├── domain/              # wspólne typy i kontrakty ports
│   │   ├── infrastructure/      # PostgreSQL, ClickHouse, Redis/Celery adapters
│   │   └── modules/             # moduły domenowe, patrz tabela
│   ├── migrations/versions/    # Alembic PostgreSQL
│   └── tests/
│       ├── unit/
│       ├── integration/
│       ├── api/
│       └── regression/
├── frontend/
│   ├── src/{app,api,components,features,entities,intelligence}/
│   └── tests/e2e/
├── detection-content/
│   └── {rules,sigma,fixtures,mitre,hunts,playbooks}/
├── demo/{scenarios,fixtures}/
├── infra/
│   ├── clickhouse/migrations/
│   ├── proxy/
│   └── observability/
├── scripts/
│   ├── validate_repository.py
│   └── repository_manifest.json
├── docs/
│   ├── adr/
│   ├── assets/
│   └── ...                     # raporty i kontrakty domenowe
└── .github/workflows/phase0.yml
```

## Moduły backendu

| Katalog w `backend/app/modules/` | Odpowiedzialność |
| --- | --- |
| `auth`, `users` | Sesje, role i użytkownicy; source credentials oddzielone od ról ludzkich |
| `ingestion` | Admission, batch, inbox/outbox, idempotencja, kwarantanna |
| `normalization` | Rejestr parserów i schema mapping |
| `events` | Event repository, bounded query i projekcje ClickHouse |
| `detections` | Native rules, Sigma, lokalny TI match, evaluator, stan okien, rule testing |
| `alerts` | Match → alert, explanation, wersje evidence i powiązania |
| `correlation` | Silne relacje, komponenty i decyzje grupowania |
| `incidents` | Case lifecycle, notes, evidence, timeline i investigations promotion |
| `attack_timeline` | Chronologia oryginalnych dowodów aktywnych alertów sprawy, kontrola źródła i stronicowanie |
| `mitre` | Wersjonowany katalog i walidacja mappingu |
| `risk` | Czysty algorytm i snapshoty obliczeń |
| `entities` | Konserwatywna tożsamość obserwacji, indeks dowodów i ograniczone zapytania profili |
| `intelligence` | Lokalny katalog IOC, niezmienne rewizje, dokładne dopasowania typowanych pól i provider interface |
| `hunting` | Saved queries, bookmarks, investigations, draft detekcji |
| `soar` | Definicje, run/step ledger, allowlista simulation actions |
| `audit` | Append-only zapis zdarzeń audytowych i kontrolowany odczyt |
| `reporting` | Metryki SOC i snapshoty raportów |

Pliki `service.py`, `domain.py`, `ports.py`, `repository.py` powstaną tylko tam,
gdzie kod uzasadnia podział. Nie generujemy identycznych pustych warstw w każdym
module. Pure domain może korzystać ze wspólnego modelu, ale nie z transportu HTTP.

## Content, migracje i testy

`detection-content` to wersjonowana treść z fixtures, metadanymi i pochodzeniem,
nie wykonywalne pluginy. `demo` emituje logi; nie ma prawa do repozytorium alertów.
`backend/tests/integration` używa prawdziwych usług. `frontend/tests/e2e` sprawdzi
interakcję przeglądarki z API, włącznie z odmowami uprawnień.

`compose.yaml`, Dockerfile backendu, pyproject/package.json, lockfile i migracje
SQL należą do istniejącego runtime. Nowe moduły używają tego samego obrazu
i migratora, zamiast tworzyć osobne usługi. `infra` oddziela konfigurację
deploymentu od domeny. Bieżące wyniki Etapu 9 zapisuje
[raport walidacji UEBA](validation-ueba.md); wcześniejsze
wyniki pozostają w raportach właściwych etapów.

## Walidacja szkieletu

[Manifest](../scripts/repository_manifest.json) wymienia wymagane katalogi i dokumenty.
[Walidator](../scripts/validate_repository.py) sprawdza je bez zewnętrznych bibliotek,
wraz z numeracją 21 faz, 37 wymagań, co najmniej sześcioma ADR, linkami lokalnymi
i formatem tekstu. Indeks obejmuje obecnie ADR 0001–0015.
Nie pobiera stron z linków internetowych i nie testuje renderowania diagramów Mermaid.

Moduł `backend/app/modules/ueba` zawiera odczyt, weryfikację i czyste statystyki
aktywności encji. `backend/app/api/ueba.py` udostępnia analizę dnia, a
`frontend/src/ueba` dołącza ją do istniejących profili. [Kontrakt](ueba.md).

## Etap 10 — aktualizacja 2026-10-08

`backend/app/modules/soar` zawiera schemas/models/evidence/actions/service/
processing/views, a `backend/app/api/soar.py` obsługuje kontrakt HTTP.
`backend/app/soar.py` uruchamia osobny proces Compose. Migracja `0012_soar`
jest bieżącym head. `frontend/src/soar` zawiera edytor, launcher, historię
i powiadomienia. Testy domenowe są w dwóch `test_soar.py`, a panelu w
`frontend/tests/soar.test.tsx`. [Dokumentacja](soar.md), [raport](validation-soar.md).
