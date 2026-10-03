# Walidacja Etapu 4 — MITRE ATT&CK

Data: 2026-10-03. Punkt wyjścia: `ead4ac6`.
Stan: Etap 4 zaimplementowany, zweryfikowany i uruchomiony w głównej aplikacji.
Wspólna regresja Linux: 1102 passed, 882,32 s; branch coverage 92%.
Panel: 79 passed; skrypty: 31 passed. Wyniki wcześniejszych etapów
pozostają dowodami historycznymi, a nie składowymi nowego przebiegu.
[Zakres i plan](mitre.md), [ADR 0010](adr/0010-versioned-attack-mappings.md).

## 1. Zakres

Lokalny przypięty katalog Enterprise ATT&CK, walidacja aktywnych technik,
subtechniques i powiązań z tactics. Osobne historyczne mapowania nowych
alertów, metadane reguł i szczegółów oraz rzeczywiste agregacje pokrycia.
UI wskazuje zakres, wersję, braki i znaczenie candidate association.
Dotychczasowe dowody i risk history zachowują swoją treść.

## 2. Dodane pliki

- Backend: `app/api/mitre.py`, `app/modules/mitre/{__init__,catalogue,coverage,
  mapping,models,schemas,service}.py`; dane `data/{LICENSE.txt,README.md,
  enterprise-attack-19.2.json,enterprise-attack-19.2.sha256}`.
- Migracja `backend/migrations/versions/0008_mitre.py`; unit `test_mitre.py`,
  integracje `test_mitre.py` i `test_mitre_security.py`.
- Panel: `frontend/src/mitre/{types,permissions,filters,useCoverage,MitreMapping,
  MitreCoverage}.ts/tsx`, `mitre.css`, testy `mitre.test.tsx` i fixtures.
- Ekstraktor `scripts/prepare_mitre_catalog.py` i osiem testów stdlib
  `scripts/tests/test_prepare_mitre_catalog.py`.
- Dokumentacja: `mitre.md`, ADR 0010 i ten raport.

## 3. Zmienione pliki

- Backend: `app/api/{alerts,correlations,detections,health}.py`, `app/main.py`,
  `app/modules/alerts/{models,schemas}.py`, `correlation/{contracts,persistence}.py`,
  `detections/processing.py`, `incidents/{schemas,views}.py`, `migrations/env.py`;
  istniejące testy `tests/integration/{test_risk,test_storage}.py` aktualizują head.
- Panel: `src/{Alerts,App}.tsx`, `src/{api,types}.ts`,
  `src/detections/{Correlations,SingleEventRules}.tsx`,
  `src/incidents/{IncidentSummary.tsx,types.ts}` oraz `frontend/README.md`.
- Infrastruktura i instrukcje: `.gitignore`, `compose.yaml`, główny README,
  `backend/README.md`, `infra/README.md`, `scripts/README.md`.
- Dokumentacja: `docs/{api-contract,architecture,data-model,implementation-plan,
  requirements-traceability,soc-expansion-plan,validation}.md` i `docs/adr/README.md`.

Integracja dodaje mapowanie w zapisie nowych alertów i metadata/details,
import modeli migracji oraz head w readiness. Panel zmienia nawigację i pokazuje
nazwy; pozostałe instrukcje dokumentują scope i granice dowodu.
`.gitignore` wyłącza spod ogólnej reguły `data/` wyłącznie publiczny
katalog `backend/app/modules/mitre/data`; lokalne dane i sekrety pozostają ignorowane.

## 4. Endpointy

GET `/api/v1/mitre/catalog` i `/api/v1/mitre/coverage` oraz odrębne
`mitre_mapping` w istniejących odpowiedziach reguł i szczegółów.
Katalog wymaga `detections:read`; coverage wymaga również `alerts:read`
i `incidents:read`. Odczyt nie dopisuje historycznych mapowań.

## 5. Modele

`AlertMitreSnapshot` (`alert_mitre_snapshots`) i `AlertMitreMapping`
(`alert_mitre_mappings`, unikalne alert/technique/tactic). Historyczne mapowanie
zachowuje wersję/hash katalogu, politykę, hash wejścia i dokumentu oraz nazwy.
Wejście wiąże scope, event anchor i oryginalne niezmienne dowody reguły.
Trigger INSERT sprawdza zgodność indeksowanego skojarzenia z dokumentem;
downgrade odmawia zniszczenia istniejącej historii. Nowy zapis jest atomowy
z alertem, ryzykiem, automatyczną sprawą i audytem.
Runtime nie aktualizuje i nie usuwa historii. Writer aplikacji jest zaufany.

## 6. Nowe testy

43 unit backendu obejmują hash/offline, defensive copy, nieznane/wycofane ID,
parent/subtechnique/tactics, wersję polityki i walidację filtrów. Osiem głównych
integracji sprawdza reguła→pipeline→alert→sprawa, unmapped root, distinct counts,
oficjalne taktyki bez potwierdzania zamiaru, enabled/history, retry/restart,
upgrade legacy bez zmiany dowodów/ryzyka oraz transakcyjny rollback.
47 niezależnych integracji sprawdza role i każdy z trzech permissions,
anonymous/source credential oraz disabled/revoked/expired session, błędne scope
i okna bez zapisów, event time [from,to), live/replay dataset/run, FP/detach,
resolved/closed, integralność scope/kotwicy i ponownie zahashowanych metadanych,
granty, trigger i blokadę destrukcyjnego downgrade.

20 nowych testów panelu obejmuje permissions, filtry, distinct counts,
unmapped/legacy/inny katalog, loading/error/retry, zmianę zakresu/sesji/konta,
bezpieczne linki/escaping, bounded search/pagination i nazwane szczegóły.
Osiem testów ekstraktora obejmuje niepoprawne hashe przed zapisem, ochronę
istniejących plików, duplikaty, relacje, oficjalne referencje i pełny UTC.

## 7. Wykonane kontrole

| Kontrola | Wynik |
| --- | --- |
| Stan początkowy Git | Czysty `ead4ac6` |
| Baseline frontend | 59 passed, 6,92 s, przed Etapem 4 |
| Docker | Engine 29.7.2 Linux przywrócony, istniejące kontenery Etapu 3 uruchomione przez start |
| Główny runtime po odzyskaniu Dockera | API/dependency readiness PASS; sam ten test nie sprawdza przetwarzania logów |
| Środowisko integracji | Odrębny projekt `aegis-mitre-20261003`, własne sekrety/volumes, PG/Redis/ClickHouse healthy; port proxy 18083 |
| Unit backend Windows | 721 passed, 27,41 s (678 wcześniejszych + 43 nowe); po wzmocnieniu hash/proof ponownie 43 passed, 0,53 s |
| Skupiona walidacja MITRE i storage | 61 passed, 17,37 s, Linux/Python 3.12.14; 43 unit + 8 nowe integracje + 10 storage |
| Niezależne integracje bezpieczeństwa | 47 passed, 50,52 s, Linux/Python 3.12.14 |
| Panel | 79 passed, 9,70 s (59 wcześniejszych + 20 nowe); TypeScript/lint/format PASS |
| Alternatywny Vite build | PASS, 67 modules, 261 ms; index-BsbWaAhm.js/index-DOYW_l0v.css |
| Ruff/backend format/mypy | PASS, 138 plików format i 91 source files mypy |
| Skrypty | 31 stdlib tests passed, 1,721 s (23 wcześniejsze + 8 nowe); Ruff/format nowego ekstraktora/testów PASS |
| Katalog | Dokładne odtworzenie bajtów PASS; SHA-256 afc5aec04660aa0f1f2ed495247239002695574735a57133529803f08946a339 |
| Obrazy offline i świeża migracja | PASS, 0008_mitre; wszystkie usługi healthy, obaj migratorzy exit 0 |
| Świeży publiczny runtime/panel | health/ready 200, 2 trasy MITRE i 7 risk w OpenAPI, MITRE anonymous 401, nowy JS 200 i self-only CSP; nie jest to test po zalogowaniu |
| Pełna regresja Linux | **1102 passed, 882,32 s**: 721 unit + 381 integration, bez skipped; 98 nowych backendowych przypadków względem Etapu 3 |
| Branch coverage | **92%**, 6069 statements, 1442 branches; wspólna unit/integration, bez sumowania wcześniejszych pomiarów |
| Główny launcher offline | PASS exit 0, start z SkipAdmin; 91 locked packages z hashami; standard Vite build 67 modules, 235 ms |
| Główna migracja i runtime | PASS, 0007_risk→0008_mitre; /health i /ready 200, 2 MITRE i 7 risk paths w OpenAPI, MITRE anonymous 401 |
| Panel przez główny proxy | PASS, /assets/index-BsbWaAhm.js 200, CSS index-DOYW_l0v.css i self-only CSP; publiczny smoke, bez zalogowanego browser E2E |
| Główna baza przed/po | 0 users/raw/normalized/alerts/incidents/correlation_jobs/scopes/risk_calculations; nowe mapowania 0; zachowano .env i volumes |
| Fizyczny restart detector/correlator | PASS, oba running=true po restarcie; te procesy nie mają własnego healthcheck, przetwarzanie dowodzą integracje |
| Spójność wersji | Zgodna kanoniczna suma lokalnych źródeł, pełnej regresji, świeżego API i głównego API: 58afcef3ad5c19388224d17a2cd2b36ad26ff6abbddb4123b9610fa1fd455315 |
| Sprzątanie własnego testu | 0 pozostałych baz PostgreSQL aegis_test_%; świeży stos: 0 użytkowników; cały stos testowy zatrzymany, volumes zachowane |
| Repozytorium | Walidator: PASS, 311 text files, 43 required directories, 21 phases, 37 requirements, 10 ADRs; git diff --check PASS |

Pełny wynik 1102 obejmuje dotychczasowe 1004 przypadki i 98 nowych, a nie sumę
dwukrotnie wykonanych testów skupionych. Branch coverage dotyczy procesu pytest;
osobne procesy HTTP/Celery/daemon mają testy zachowania, bez deklaracji ich
instrumentowanego pokrycia. Oryginalne pliki BuiltinRule nie mają diff.

Odtworzenie po przygotowaniu własnego środowiska Compose i zależności:

```text
pytest --cov=app --cov-report=term-missing -p no:cacheprovider -q --tb=short
```

W kontenerze read-only należy ustawić `COVERAGE_FILE=/tmp/.coverage`.
Kontrole panelu korzystają z przypiętych Node 24.19.0/pnpm 11.19.0;
szczegóły poleceń są w frontend/README.md. Skrypty sprawdza
`python -m unittest discover -s scripts/tests -q`.

## 8. Problemy techniczne i ograniczenia

Docker był zatrzymany na początku tego przyrostu. Standardowy start ponownie
zakończył się potwierdzonym w lokalnym logu błędem AF_UNIX
`Docker/run/dockerInference`. Zweryfikowano ścieżki procesów Docker Desktop,
zatrzymano je i sprawdzono, że już nie pracują. Dwa konkretne, rzeczywiste
katalogi komunikacji odłożono w tym samym rodzicu do zachowanych kopii:
`run.aegis-mitre-backup-27f1fd8fee5343299705e7c12829fc3d` i
`docker-secrets-engine.aegis-mitre-backup-ee647ac6f52c4a218019aeb7a96b18d9`.
Oficjalne `docker desktop start --timeout 120` przywróciło silnik,
a start istniejących kontenerów przywrócił aplikację. Bazy, volumes, WSL
i konfiguracja zostały zachowane. Przyczyny wcześniejszego zatrzymania
Desktop nie ustalono.

Mapowanie ATT&CK jest wskazówką do analizy. Nie potwierdza ataku ani intencji
realizacji wszystkich powiązanych taktyk; składnik T ryzyka pozostaje unknown.
Pełny graf/storyline, filtry event search, import Sigma i przypisywanie nowych
reguł są kolejnymi przyrostami. Historyczne alerty bez nowego snapshotu
pozostają jawnie historyczne/niezmapowane.

Niezależny przegląd przed regresją wzmocnił wiązanie hash wejścia ze scope,
kotwicą i dowodami alertu. Ekstraktor odrzuca duplikaty identyfikatorów i
niepełny timestamp UTC; bajty katalogu pozostały identyczne. Poprawiono dwa
oczekiwania fixtures: Medium nie tworzy automatycznej sprawy, więc test
unmapped root dołącza alert do sprawy ręcznej, a dwie obserwacje porażek/sukcesu
mają jedną automatyczną sprawę High. Nie zmieniono tego zachowania produkcji.

Pierwsza próba pomiaru coverage nie rozpoczęła testów: `/app` jest read-only.
Końcowy przebieg używa `COVERAGE_FILE=/tmp/.coverage`, zachowując ograniczenia
kontenera. Porównanie źródeł normalizuje UTF-8/LF oraz sortuje pełne POSIX paths
jednakowo na Windows i Linux, uwzględniając Python, migracje i wszystkie pliki
lokalnego katalogu/licencji. Lokalne źródła, świeże API i kontener pełnej regresji
mają SHA-256 `58afcef3ad5c19388224d17a2cd2b36ad26ff6abbddb4123b9610fa1fd455315`.

Hostowane CI pozostaje niewykonane, ponieważ repozytorium nie ma remote.
Ręczny test po zalogowaniu nadal jest otwarty: wcześniejsza automatyczna
kontrola odrzuciła tworzenie tymczasowego administratora jako niezatwierdzoną
zmianę uprawnień. Nie obchodzono tej decyzji i nie tworzono ręcznego konta.

## 9. Następny etap

Etap 5 — bezpieczny import i wykonanie obsługiwanego podzbioru Sigma.
Nowe reguły będą mogły korzystać ze zweryfikowanego lokalnego katalogu,
z zachowaniem własnych wersji i niezmiennych dowodów.
