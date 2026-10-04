# Walidacja Etapu 5 — Sigma

Data aktualizacji: 2026-10-04. Punkt wyjścia: `64f837a`.
Stan: Etap 5 zaimplementowany, zweryfikowany automatycznie i uruchomiony
w głównej aplikacji. Wspólna regresja Linux: **1361 passed**,1163,79s;
branch coverage92%. Panel113passed; skrypty31passed.
[Zakres i plan](sigma.md), [ADR 0011](adr/0011-versioned-sigma-rules.md).

## 1. Zakres

Import, walidacja, niezmienne rewizje, jawna publikacja, test i wykonanie
podzbioru Sigma. Ryzyko v3 z deklarowaną severity i mapowanie MITRE.

## 2. Dodane pliki

- Backend: `app/api/sigma.py`, `app/modules/sigma/{__init__,compiler,conditions,
  yaml_support,evaluator,models,schemas,service}.py`, migracja `0009_sigma.py`.
- Testy backendu: unit `test_sigma_compiler.py`, `test_sigma_service.py`;
  integracje `helper_sigma.py`, `test_sigma.py`, `test_sigma_security.py`.
- Panel: `src/sigma/{types,limits,useSigmaScope,useSigmaResource,SigmaCapabilities,
  SigmaRules,SigmaEditor,SigmaDetails,SigmaTest,SigmaFailure}.ts/tsx`, `sigma.css`;
  testy `sigma.test.tsx`, `sigmaAlerts.test.tsx`, `sigmaFixtures.ts`.
- Własna przykładowa reguła `detection-content/sigma/aegis_windows_encoded_powershell.yml`.
- Dokumentacja: `sigma.md`, ADR 0011 i ten raport.

## 3. Zmienione pliki

- Backend: health/readiness, body limits, router registration, alert type,
  orchestration detektora, historyczny proof i configured coverage MITRE,
  kontrakt/arytmetyka/pochodzenie ryzyka oraz import modeli migracji.
- Istniejące integracje storage/risk/MITRE aktualizują bieżący head na0009,
  zachowując historyczne downgrade guards.
- Panel: API POST z If-Match, trzecia zakładka detekcji, typ/badges alertów
  i powiązań spraw oraz instrukcja frontendu.
- Dokumentacja i manifest: README/backend/detection-content/infra, API/model/
  architecture/detection/risk/plan/traceability/validation oraz indeks ADR.
- Compose używa końcowych obrazów `sigma-stage5`, wybranych po pełnej regresji.

Zależności runtime: PyYAML 6.0.3;
dev: types-PyYAML 6.0.12.20260906. Dotychczasowe wersje i hashe zachowane.
Dotychczasowy colorama 0.4.6 ma jawną deklarację dev, aby generowanie lockfile
na Linux nie usuwało pakietu potrzebnego także na Windows. Runtime 48 i dev
93 unikalne pakiety; offline wheelhouse zweryfikowany dla wszystkich 93.

## 4. Endpointy

`/api/v1/sigma`: GET capabilities, GET rules, GET rules/{id},
POST validate, POST test, POST rules, POST rules/{id}/versions,
PATCH rules/{id}: osiem metod na sześciu ścieżkach.
Odczyt/walidacja wymagają detections:read, test detections:test,
import/rewizje detections:import, publikacja detections:publish.
Mutacje rewizji/publikacji używają If-Match; import pozostaje wyłączony.
[Dokładny kontrakt](api-contract.md).

## 5. Modele

Append-only SigmaRule/SigmaRuleVersion, projekcja RuleDeployment,
historyczny snapshot alertu i osobne severity_baselines risk-policy-v3.
Runtime ma SELECT/INSERT do definicji; kontrolowana funkcja wybiera istniejącą
rewizję w deployment. Nowa rewizja wyłącza regułę. Granica aplikacyjnego autora
INSERT pozostaje zaufana; nie deklarujemy odporności na przejęty runtime.

## 6. Nowe testy

157 przypadków kompilatora/wykonawcy, 28 unit proof/ryzyko, 25 primary
integrations i 49 independent security integrations: **259 nowych przypadków**.
Baseline backendu1102 daje1361 w bieżącej kolekcji, unit906 i integration455.
Panel dodaje34 do79 wcześniejszych:113. Skrypty zachowują31 przypadków.

Przypadki obejmują UTF-8/65536bajtów, bezpieczny YAML i budżety AST,
AND/OR/NOT, aliasy i zakresy liczb; import/revision/history/idempotence,
role,15 wyścigów authority-after-lock, optimistic conflicts, audit rollback,
append-only/granty/downgrade,100reguł/20rewizji i25eventów.
Rzeczywisty pipeline sprawdza alert/risk/MITRE/autoincident, retry i live/replay.
Zweryfikowano też zamknięcie manifestu korelacji przy włączonej Sigma.
Historyczny fixture v2 pochodzi z realnego builtin proof; odtworzono starszy
kontrakt wejścia/hash polityki, następnie sprawdzono niezmieniony GET po
0008→0009 oraz osobną jawną rekalkulację v3. Główna baza nie zawiera historii.
Panel sprawdza role/konflikty, drafts i late responses, typ alertu,
D-only/unknown C/E oraz odrzucenie wadliwego kodowania pliku.

## 7. Wyniki

Końcowy wspólny przebieg: **1361PASS1163,79s**, bez pominiętych przypadków,
Linux/Python3.12.14; unit906 i integration455. Coverage92%,6990statements
i1780branches. To pomiar procesu pytest; osobne API/workery/daemony mają
behaviour proof w integracjach, nie są objęte tą instrumentacją.

157 focused compiler tests PASS, 0,97 s. Ruff/format i strict Mypy dla czterech
plików parsera/wykonawcy PASS. To wynik modułu, nie wspólnej regresji etapu.
Primary integrations25PASS54,40s; security49PASS96,48s. Pierwszy primary
przebieg miał31PASS i jeden błędny oczekiwany licznik konfiguracji techniki:
trzy istniejące reguły+Sigma dają cztery. Poprawiono oczekiwanie i powtórzono
zestaw. Storage10 przypadków przeszło w tym pierwszym przebiegu.
Root initial unit906PASS36,23s. Ruff check i format151plikówPASS;
strict Mypy100source filesPASS; pip check test imagePASS.
Panel113PASS11,56s, TypeScript/ESLint/PrettierPASS; alternatebuild77modułów383ms.
JS `index-DjwWTB1T.js`363,71kB/gzip105,02kB, CSS18,86kB/gzip5,07kB.
Skrypty31PASS1,753s na pełnym runtime spoza OneDrive. Pierwszy przebieg
w `.venv` miał pojedynczy timeout lokalnego testowego HTTP; kod nie zmieniony.

Fresh projekt `aegis-sigma-20261004`, port18084, własne sekrety i volumes:
schema0009, users/data/Sigma0. API/dependencies readinessPASS;
public health/ready200, osiem metod Sigma w OpenAPI, anonimowy odczyt401.
Bundle Sigma i CSPself-only sprawdzone; to nie jest zalogowany przebieg UI.
Kod backendu/migracji/katalogu w lokalnym źródle, fulltest i fresh API ma hash
`da0e18aa6e2a80fba281a041a4b7e7e5b5aa1712c2e1f173ebce790beea50b96`.
Hash nie obejmuje panelu, testów ani zależności; lockfile i bundle mają osobny dowód.
Główna aplikacja: launcher offline `start -SkipAdmin` PASSexit0, migracja
0008→0009, przygotowanie93hash-verifiedpackages i standardowy build panelu
77modułów307ms. Bundle `index-DjwWTB1T.js` i CSS `index-MWpSMFQl.css`
zgodne z końcowym testowanym panelem. Public HTTP przez port8080:
health/ready/OpenAPI200, routes Sigma obecne, anonimowy Sigma/MITRE401,
CSPself-only. Kod main API ma ten sam hash co źródło/fresh/fulltest.
Readiness nie jest dowodem przetworzenia prawdziwych danych w pustej bazie.

Główne liczniki users/raw/normalized/alerts/incidents/correlation/risk/MITRE
pozostają0 przed i po. Nowe Sigma rules/versions/deployments też0;
nie importowano przykładu ani nie tworzono kont. Fizyczny restart main
detector/correlator PASS: oba `.State.Running=true`,2026-10-04T09:06:03Z.
Te dwa procesy nie mają healthcheck; komunikat Compose „Healthy” sam nie
ustanawia ich zdrowia. Przepływ danych i wznowienie mają osobny dowód testowy.
Po regresji0baz `aegis_test_%`, fresh users/data0. Stos testowy zatrzymano
z zachowaniem jego wolumenów; główna aplikacja pozostaje uruchomiona.
Repository validator344textfiles/44required directories/21phases/37requirements/
11ADRsPASS. `git diff --check`PASS; brak hostowanego CI.

## 8. Problemy i granice dowodu

Docker Desktop ponownie zatrzymał się na błędzie AF_UNIX `dockerInference`.
Log potwierdził przyczynę; zatrzymano procesy z jego katalogu instalacji
i zachowano kopie dwóch sprawdzonych katalogów komunikacji. Engine 29.7.2
ponownie odpowiada. Nie ustalono trwałej przyczyny powrotu błędu.

Część starego lokalnego `.venv` jest niedostępna przy wyłączonym OneDrive.
Automatyczna kontrola odrzuciła start OneDrive także po zgodzie użytkownika,
uzasadniając to brakiem określonego zakresu danych i konta synchronizacji.
Nowe pakiety zainstalowano sprawdzonym pip z runtime poza OneDrive;
odczyt parsera działa, a dalsze testy korzystają z Dockera.

Ręczne logowanie w panelu nie jest potwierdzone: wcześniejsza kontrola
odrzuciła stworzenie tymczasowego administratora. Automatyczne konta testowe
powstają wyłącznie w izolowanych bazach i nie zastępują tego dowodu.

Audyt podatności online wymaga wysłania48nazw i wersji bibliotek do PyPI.
Automatyczna kontrola odrzuciła ten transfer przed wykonaniem; osobna zgoda
użytkownika pozostaje oczekiwana. Przygotowano lokalny, przeglądalny inventory.
Offline `pip-audit --dry-run`, z wyłączoną siecią, odczytał48pakietów (exit0),
ale nie sprawdził podatności. Jego ogólny komunikat „No known vulnerabilities
found” nie stanowi dowodu wyniku skanowania. Nie deklarujemy aktualnego
braku podatności. Hostowane CI i pełny zalogowany browser E2E nie były wykonane.

## 9. Kolejny etap

Etap 6: encje host/użytkownik/IP/proces. Bramka funkcjonalna Sigma została
zamknięta; granice dodatkowego audytu online i ręcznego UI opisano powyżej.
