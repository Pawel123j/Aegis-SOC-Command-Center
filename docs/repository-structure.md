# Struktura repozytorium

Status: układ docelowy z PHASE 0. Fundament backendu, testy i infrastruktura PHASE 1
są ukończone i zweryfikowane w Compose (2026-09-28); wyniki zawiera
[raport walidacji](validation.md). Katalogi przyszłych modułów zachowują `.gitkeep`.
Moduł `ingestion`, API `sources/events`, proces `relay`, migracja `0002_ingestion`
i testy przyjęcia zdarzeń powstały w PHASE 2. Przyszłe moduły
nie zawierają pustych funkcji lub fałszywych endpointów. Poniżej ścieżki istniejącego
szkieletu i odpowiedzialności planowanego kodu.

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
│   ├── src/{app,api,components,features}/
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
| `detections` | Native rules, Sigma, evaluator, stan okien, rule testing |
| `alerts` | Match → alert, explanation, wersje evidence i powiązania |
| `correlation` | Silne relacje, komponenty i decyzje grupowania |
| `incidents` | Case lifecycle, notes, evidence, timeline i investigations promotion |
| `mitre` | Wersjonowany katalog i walidacja mappingu |
| `risk` | Czysty algorytm i snapshoty obliczeń |
| `intelligence` | IOC, wersje reputacji, inventory i dostawcy kontekstu |
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
`backend/tests/integration` użyje prawdziwych usług. `frontend/tests/e2e` sprawdzi
interakcję przeglądarki z API, włącznie z odmowami uprawnień.

Nie ma jeszcze `compose.yaml`, Dockerfile, pyproject/package.json ani migracji SQL.
Powstaną razem z działającym runtime, w fazach 1/3/13. Sam pusty manifest zależności
nie stanowi implementacji fundamentu. `infra` oddziela konfigurację deploymentu od domeny.

## Walidacja szkieletu

[Manifest](../scripts/repository_manifest.json) wymienia wymagane katalogi i dokumenty.
[Walidator](../scripts/validate_repository.py) sprawdza je bez zewnętrznych bibliotek,
wraz z numeracją 21 faz, 37 wymagań, sześcioma ADR, linkami lokalnymi i formatem tekstu.
Nie pobiera stron z linków internetowych i nie testuje renderowania diagramów Mermaid.
