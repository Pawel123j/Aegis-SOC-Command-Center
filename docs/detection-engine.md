# Detection Engine — projekt kontraktu

**Status: projekt PHASE 0. Silnik, importer Sigma, endpointy i testy opisane poniżej nie są jeszcze zaimplementowane.** Dokument definiuje zachowanie do realizacji i bramki akceptacji, a nie deklarację działających funkcji.

## Granice modułu

Silnik przyjmuje niezmienne `NormalizedSecurityEvent`, wersję reguły oraz jawny kontekst wykonania. Zwraca dopasowania wraz z dowodami. Czysty evaluator nie wykonuje SQL, HTTP, poleceń systemowych ani zmian incydentów. Orkiestrator zapisuje stan okien, dopasowania, alerty i outbox w PostgreSQL. ClickHouse przechowuje archiwum; nie jest źródłem synchronizacji bieżącego okna. Redis/Celery przenosi zadania, a trwały inbox PostgreSQL pozwala je odzyskać.

Wszystkie klucze wyników zawierają zakres danych: `dataset_id`, `mode` (`live` albo `replay`) i `run_id` dla replay. Wersja normalizacji, parsera, evaluatora, mapowania pól i reguły jest częścią pochodzenia wyniku. Pole kanoniczne to `event.outcome` o wartościach `success`, `failure` albo `unknown`; `result = "failed"` jest aliasem query tłumaczonym na `event.outcome = "failure"`, nie dodatkowym polem normalized JSON.

## Czas, kolejność i watermark

Proponowane parametry `detection-policy-v1`:

| Parametr | Wartość | Znaczenie |
|---|---:|---|
| `allowed_lateness` | 120 s | Maksymalna różnica `received_at - timestamp` dla online |
| `max_future_skew` | 30 s | Maksymalna różnica `timestamp - received_at` dla online |
| Brute force | 10 failures / 5 min | Ruchome okno, próg włącznie |
| Najdłuższa sekwencja | 30 min | Ograniczenie stanu i zakresu odtwarzania |
| Grupowanie alertów threshold | 5 min UTC | Ogranicza powiadomienia; nie zmienia ruchomego okna detekcji |

`timestamp` to czas zdarzenia, `received_at` to zaufany czas przyjęcia przez serwer; oba są UTC o jawnej precyzji mikrosekund. Czas klienta nie steruje zegarem silnika. Brak lub błędny znormalizowany timestamp po pracy parsera daje błąd walidacji albo kwarantannę zgodnie z kontraktem ingestion, bez podstawiania bieżącego czasu. Poprawny event kwalifikuje się do online, gdy:

```text
received_at - 120s <= timestamp <= received_at + 30s
```

Starszy event zostaje zachowany jako `late_event`, zbyt przyszły jako `clock_skew_event`; oba są widoczne w diagnostyce i mogą wejść do jawnego replay. Nie przesuwają watermarku, nie są cicho odrzucane i nie dopisują się do już zamkniętych wyników online. Retry używa pierwotnego `received_at`, nie zegara kolejnego workera.

Watermark `W = B - 120s`, gdzie `B` jest monotoniczną, zamkniętą barierą ingress. Nie wolno obliczać jej jako `MAX(timestamp)` ani `MAX(received_at)`. Bariera potwierdza, że:

1. Nie istnieje transakcja przyjęcia, która może później zatwierdzić event z `received_at <= B`.
2. Wszystkie trwale przyjęte rekordy do `B` są znormalizowane i uwzględnione w stanie albo jawnie, trwale skierowane do kwarantanny z przyczyną.
3. Zapis stanu i przesunięcie checkpointu są zatwierdzone w PostgreSQL.

Pierwsza implementacja może zamykać epoki przyjęcia pod wspólną blokadą admission/barrier w PostgreSQL. Nadawanie `received_at` musi respektować tę samą blokadę/fencing. Sam numer sekwencyjny nadany przed commit nie wystarcza. Trwałe heartbeaty zamykają puste epoki, dzięki czemu brak nowych logów nie zatrzymuje finalizacji. Backlog zatrzymuje barierę; awaria workera nie jest powodem do przeskoczenia danych.

Evaluator rozstrzyga kotwice `t <= W` w porządku `(timestamp, event_id)`. Kotwica to czas eventu kończącego dopasowanie. Równe timestampy porządkujemy technicznie po ID, ale nie uznajemy tego za dowód kolejności przyczynowej. Sekwencje wymagają ściśle rosnących czasów etapów. Przetworzenie w innej kolejności dostarczenia daje ten sam zbiór dopasowań. Skok czasu serwera wstecz nie cofa watermarku; wykrycie dużego skoku w przód wstrzymuje jego awans i zgłasza problem zegara.

Koszt świadomej decyzji: finalna detekcja online pojawia się po buforze 120 s oraz czasie backlogu. Mierzymy osobno event-time latency i czas obliczeń. Szybkie, prowizoryczne alerty pozostają poza pierwszym kontraktem, aby nie wymagać wycofywania fałszywych dopasowań.

## Typy detekcji

| Typ | Semantyka i przykład |
|---|---|
| `single_event` | Predykat na jednym evencie, np. rozpoznany proces PowerShell i podejrzane argumenty; kotwicą jest ten event |
| `threshold` | Liczba unikalnych eventów spełniających predykat w ruchomym oknie dla konkretnego klucza grupy |
| `sequence` | Uporządkowane etapy z wymaganymi wspólnymi tożsamościami i maksymalnym spanem |
| `correlation` | Wersjonowany predykat nad istniejącymi dopasowaniami/alertami, przekazany do modułu korelacji; nie wywołuje ponownie siebie |

Nie tworzymy osobnego algorytmu „time-window”: threshold i sequence mają jawne okno. Natywny AST pozwala na większy zakres funkcji niż importer Sigma; brak obsługi konstrukcji Sigma nie blokuje zapisania równoważnej, jawnie natywnej reguły.

### Brute force: granice i deduplikacja

Dla każdej kotwicy failure `t` i grupy `g`:

```text
E(g,t) = unique event_id where group = g
         and event.category = authentication
         and event.outcome = failure
         and t - 5m < timestamp <= t
match iff count(E(g,t)) >= 10
```

Lewy brzeg jest wyłączny, prawy włączny. Dziewięć failures nie wystarcza. Failure dokładnie pięć minut przed kotwicą nie liczy się. Liczba prób to liczba eventów źródła, nie liczba dostarczeń Celery ani identycznych linii tekstu.

„Użytkownik lub IP” oznacza dwie jawne instancje reguły: grupowanie po stabilnym `principal_key` albo po `(source.ip, destination_host_key)`. Nie używamy `coalesce(user, ip)`. Klucz principal zawiera realm/domain i stabilny identyfikator, a dla kont lokalnych także zakres hosta. Brak wymaganego pola pomija daną instancję z diagnostyką; wszystkie braki nie tworzą grupy `null`.

Wszystkie spełniające próg kotwice są deterministycznymi dopasowaniami. Warstwa alertów grupuje je po `(scope, rule_version, group_key, floor(t / 300s))`. Pierwsza finalizowana kotwica tworzy jeden alert; kolejne dopasowania w tym samym UTC bucket aktualizują go przez nową, niezmienną rewizję evidence. Alert zachowuje `trigger_count`, pierwsze okno i pierwszą kotwicę; dodatkowo pokazuje `observed_unique_events`, unię dowodów i ostatnią kotwicę. Ten drugi licznik nie jest ponowną oceną progu w jednym wielkim oknie. Kilka eventów z identycznym timestamp widzi ten sam pełny zbiór w oknie i może dać kilka matches, lecz nadal jeden alert bucket. Dołączenie match bez zmiany evidence nie wymaga kopiowania identycznej rewizji dowodów.

Gdy watermark osiągnie koniec bucketu, jego evidence otrzymuje stan `final`; wcześniej ma stan `collecting`, mimo że każde dołączone dopasowanie jest już finalne. Event z następnego bucketu może wygenerować kolejny alert. Nie stosujemy ukrytego cooldownu uzależnionego od czasu workera. Okna przekraczające granicę 5-minutowego bucketu nadal wykrywają próg. Reguły po user i IP mogą wskazywać te same eventy; risk engine nie liczy ich jako dwóch niezależnych sygnałów.

### Sekwencje

`failures_then_success_v1`: dla success w czasie `s` szukamy co najmniej 10 unikalnych failures w `(s-5m, s)`, przy identycznym `(principal_key, destination_host_key, source.ip)`. Ostatni failure musi poprzedzać success. Kotwica to success; jedno dopasowanie na success ID. Dowody zawierają wszystkie pasujące failures oraz success. Sekwencja nie wymaga, aby osobny alert brute-force był już zapisany: oba wyniki wynikają z tych samych eventów. Sukces innego użytkownika za tym samym NAT nie kończy sekwencji.

`new_admin_v1`: utworzenie lokalnego konta, a następnie dodanie tego konta do uprzywilejowanej grupy, z `0 < t_add - t_create <= 30m`. Wspólne są stabilne ID **konta docelowego**, realm i host; konto wykonującego administratora jest odrębną encją. Niejednoznaczne ponowne użycie username nie wystarcza. Jedno dopasowanie na event dodania do grupy; przy kilku create wybieramy najpóźniejszy poprzedzający create tej samej tożsamości, z rozstrzygnięciem remisu po event ID.

Stan każdej reguły ma osobny namespace wersji. Włączenie/zmiana reguły ustanawia `effective_from` na bezpiecznej granicy watermarku i wymaga zasilenia bufora poprzednich 30 min przed oceną nowych kotwic. Nowa wersja nie dziedziczy liczników starej. Historyczne wyniki wymagają replay. Wyłączenie zatrzymuje nowe kotwice od `effective_to`; istniejące alerty pozostają czytelne.

## Dostarczenie co najmniej raz i odtwarzanie

Idempotencja eventu: `(dataset_id, mode, run_id, source_id, source_event_id)` albo jawny klucz klienta w tym samym scope. Live ma stały namespace run. Serwer sprawdza hash kanonicznego payloadu: ponowienie tego samego ID i treści zwraca wcześniejszy wynik; to samo ID z inną treścią jest konfliktem. Nie deduplikujemy wyłącznie po treści: dziesięć rzeczywistych, identycznych prób może oznaczać dziesięć eventów. Replay istniejącego archiwum referencjonuje oryginalne immutable event IDs przez manifest membership, zamiast je ponownie ingestować; klucze wyników zawsze należą do nowego run.

Klucz dopasowania jest hashem kanonicznej struktury: namespace, reguła/wersja, evaluator/schema version, grupa oraz anchor ID. Alert threshold używa klucza bucketu opisanego wyżej; single/sequence używa match key. Ograniczenia `UNIQUE` w PostgreSQL, checkpoint i outbox w tej samej transakcji zapewniają jeden efekt widoczny po dowolnej liczbie retry. Sam lock w Redis nie jest gwarancją poprawności.

Replay ma jawne żądane `[a,b)`, ograniczenie wielkości, wersje reguł i zamknięty manifest wejściowych eventów. Gdy wybrano threshold z grupowaniem alertów, manifest ustanawia efektywny zakres wyniku `[a_eff,b_eff)` przez zaokrąglenie a w dół, a b w górę do granic 5-minutowych bucketów; zachowuje i pokazuje także oryginalne żądanie. Bez takiego grupowania efektywny zakres jest równy żądanemu. Wczytujemy halo `[a_eff-30m,a_eff)` i eventy `[a_eff,b_eff)`, emitując dopasowania o kotwicach wyłącznie w efektywnym zakresie. Dzięki temu nie udajemy pełnego alertu bucket na podstawie fragmentu jego okna.

Nie wystarczy ponownie sprawdzić spóźnionego eventu końcowego: spóźniony **pierwszy lub środkowy** element może zmienić wynik późniejszej sekwencji. Dla wskazanego late eventu w x narzędzie proponuje zakres wpływu kotwic `[x,x+30m+1µs)`, a następnie stosuje wyrównanie i halo; pojedyncza sekwencja o maksymalnym spanie kończąca się dokładnie w x+30m mieści się w zakresie. Dla zbioru late events bierze obwiednię tych zakresów z limitem rozmiaru zadania. Zbiór wejściowy jest sortowany deterministycznie i uruchamia ten sam evaluator. Wynik z węższego ręcznego zakresu nie oznacza sprawdzenia wszystkich skutków spóźnienia.

Reanaliza korelacji używa dodatkowo 30 min halo alertów z obu stron; uzyskanie tych alertów może wymagać do 60 min wcześniejszych eventów. Orkiestrator oblicza halo z wersji reguł, nie z założenia „zawsze pięć minut”. Halo daje kontekst lokalny, ale nie gwarantuje identycznego membership jak live: wcześniejsze komponenty wpływają na zachłanne łączenie. Dokładne odtworzenie wymaga checkpointu członkostwa i całego potrzebnego stanu albo pełnego replay od ustalonej granicy resetu. Bez tego wynik ma `reanalysis`, a przy brakach halo także `incomplete_context`; nie jest przedstawiany jako rekonstrukcja live. Szczegóły zawiera kontrakt korelacji.

Demo używa `dataset_id`, `mode=replay`, `run_id` i manifestu z jawnym zamknięciem wejścia, przez to samo API, inbox, parsery, normalizację i silniki. Finalizacja zamkniętego zbioru nie wymaga czekania 120 s ani publicznego endpointu do zmiany zegara. Wyniki są odseparowane od online, opisane w UI jako demo/replay i nie zwiększają metryk operacyjnych live. Ponowienie tego samego run i manifestu jest idempotentne; zmiana wejścia wymaga nowego run. Promocja replay do pracy analityka jest jawną, audytowaną operacją, bez nadpisywania historii live.

Stan roboczy można usuwać dopiero po watermark i pełnym maksymalnym lookback oraz po potwierdzonym zapisie evidence/archiwum. Konfiguracja ustala limity liczby grup, eventów w grupie i rozmiaru pojedynczego zadania. Ich przekroczenie daje backpressure i trwały błąd operacyjny, nie reset licznika. Kwarantanna danych wykluczonych z detekcji jest widoczna jako luka coverage.

## Niezmienne wersje reguł

`rule_id` identyfikuje rodzinę, `rule_version` jej niezmienną treść. Wersja zawiera: nazwę, opis, severity, confidence `0..100`, MITRE mapping, false-positive guidance, references, autora, czas utworzenia, źródłowy YAML/AST, hash, wersję kompilatora i schematu pól. `enabled`, aktualna aktywna wersja oraz `updated_at` należą do audytowanej konfiguracji wdrożenia. Zmiana severity, predykatu lub mapowania tworzy nową wersję. Usunięcie aktywnej konfiguracji nie usuwa historycznej treści użytej w alertach.

Cykl życia: import → walidacja → skompilowany AST → fixtures/test run → wersja gotowa → aktywacja. Rule testing uruchamia izolowany, ograniczony zasobowo replay; nie wysyła powiadomień ani nie uruchamia SOAR.

## Sigma: wąski, jawny profil importu v1

Punktem odniesienia jest [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html). Oficjalna specyfikacja definiuje m.in. mapy połączone AND, listy wartości OR oraz logiczne warunki. Aegis zapisze konkretną wersję specyfikacji i własnego profilu, zamiast deklarować pełną zgodność.

Decyzja projektu: pierwszy importer przyjmuje wyłącznie poniższy profil. To celowe ograniczenie implementacji Aegis, nie opis możliwości całej Sigmy.

| Konstrukcja | Projektowane zachowanie v1 |
|---|---|
| Jeden dokument YAML | Safe loader, brak własnych tagów, aliasów, anchorów, merge keys i duplikatów kluczy |
| `title`, `id`, `description`, `author`, `references`, `falsepositives`, `level`, `tags` | Walidowane metadane; wymagane pola Aegis muszą być uzupełnione przed aktywacją |
| `logsource` | Allowlista `(product, category, service)` z wersjonowaną, jednoznaczną mapą źródła i pól |
| Named selection jako mapa | AND między polami; scalar lub niepusta, jednorodna lista scalarów; OR między wartościami |
| Wartości integer | Ścisłe porównanie do pola integer; brak automatycznego rzutowania string na liczbę |
| String | W pierwszym profilu wymaga `cased`; exact albo pojedyncze `contains`, `startswith`, `endswith` razem z `cased` |
| `condition` | Jeden string z nazwami selection, `and`, `or`, `not`, nawiasami; priorytet `not` > `and` > `or` |
| Brak pola eventu | Atom porównania daje false; `not` działa na wynik całej selection; szablon wymaga dodatniego ograniczenia źródła |
| ATT&CK tags | Walidowane względem lokalnego, wersjonowanego katalogu; nie są samodzielnym warunkiem dopasowania |

Wymóg `cased` jest restrykcyjny: zwykłe stringi Sigmy są domyślnie case-insensitive. Nie wolno importować ich jako case-sensitive bez błędu. Importer v1 zwróci `UNSUPPORTED_CASE_MODE`; przyszła pełna implementacja porównań bez rozróżniania wielkości liter będzie nowym profilem z własnymi fixture. Modyfikator `cased` jest opisany w [oficjalnym zestawieniu modyfikatorów](https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html).

Wartości zawierające `*`, `?` lub backslash są w pierwszym profilu odrzucane, aby nie udawać obsługi escape/wildcard Sigmy. Zamiast cicho zmieniać znaczenie Windows paths importer pokazuje pole i nieobsługiwaną konstrukcję. Wbudowane reguły natywne mają własne typowane operatory i nie podlegają tej restrykcji importu.

Odrzucane są ponadto: `re`, `base64`, `base64offset`, `expand`, `fieldref`, `cidr`, dowolne inne lub wielokrotnie powtórzone modyfikatory, `all`, `exists`, `null`, keyword search, listy map, lista `condition`, `1/all of ...`, aggregation pipes, Sigma correlation, filters i nieznane pola semantyczne. Metadane rozszerzeń muszą mieć jawnie zadeklarowany schemat; nie ignorujemy nieznanego klucza, który mógł zmieniać znaczenie reguły. HTTP 422 zawiera kod, ścieżkę YAML, pozycję i dozwolony profil; nie powstaje częściowo aktywna reguła.

Przykład **projektowanego** akceptowanego importu, wyłącznie do testu wykrywania jednego wariantu argumentu:

```yaml
title: PowerShell EncodedCommand — demonstrator case-sensitive
id: b78ee704-2e98-4bf8-9c58-3a8489740eed
description: Wykrywa konkretny zapis argumentu; inne warianty wymagają osobnej reguły.
author: Aegis SOC
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|cased: '-EncodedCommand'
    condition: selection
level: medium
tags:
    - attack.t1059.001
falsepositives:
    - Zatwierdzone skrypty administracyjne używające zakodowanych argumentów.
```

Nazwa procesu musi zostać zweryfikowana w produkcyjnej regule natywnej; sam token w command line nie dowodzi wykonania PowerShell. Importowana demonstracyjna reguła pozostaje nieaktywna do uzupełnienia confidence, references i pozytywnych/negatywnych fixtures. YAML ma limit 64 KiB, depth 16, 256 AST nodes, 32 selections i 128 wartości listy; evaluator nie używa `eval`, dynamicznego importu ani generowania kodu.

## Explainability i ATT&CK

Każda rewizja alertu zapisuje: co wykryto, powód i policzony predykat, zakres czasu zdarzeń, czas wykrycia, tożsamości i ich źródło, miejsca/hosty, rule ID/version/hash, evaluator/parser/schema versions, ID i hashe dowodów, MITRE mapping snapshot oraz risk calculation ID. Przykład: „10 unikalnych failures w (14:00:12, 14:05:12], próg >=10, user=realm/alice, host=h17; success 14:05:30 po 12 failures”. W UI odróżniamy brak danych od negatywnego wyniku oraz zachowanie podejrzane od potwierdzonego ataku.

MITRE nie jest etykietą dowolnie dodawaną do każdego eventu. Podejrzane nadużycie sudo może wspierać [T1548.003](https://attack.mitre.org/techniques/T1548/003/); samo poprawne sudo nie dowodzi nadużycia. [T1068](https://attack.mitre.org/techniques/T1068/) dotyczy wykorzystania podatności do eskalacji i wymaga takiej przesłanki. Utworzenie lokalnego konta i dodanie do grupy mogą być modelowane odrębnie jako [T1136.001](https://attack.mitre.org/techniques/T1136/001/) i [T1098.007](https://attack.mitre.org/techniques/T1098/007/). Mapping zachowuje wersję katalogu ATT&CK i uzasadnienie reguły.

## Plan fixtures i bramki akceptacji

Fixtures zawierają znormalizowane eventy, kolejność przyjęcia, zegar/barierę testową, wersje, oczekiwane dopasowania, alert keys, pełne evidence i przyczyny braku dopasowania. Nie porównujemy tylko liczby alertów.

| Zestaw | Wymagany wynik |
|---|---|
| 9 / 10 / 11 failures o rosnących czasach w jednym oknie | 0 / 1 / 2 matches; ostatnie dwa przypadki po jednym alert bucket przy wspólnym bucket |
| 10 failures z jednym wspólnym timestamp | 10 anchor matches, jeden alert bucket i 10 unikalnych evidence IDs |
| Dokładnie 5 min i 5 min minus 1 µs | Lewy brzeg wyłączony / event uwzględniony |
| Okno przez granicę UTC bucketu | Próg wykryty bez resetu licznika |
| Dwa źródła retry jednego eventu | Jeden event w liczniku; realne różne source event IDs pozostają oddzielne |
| Failure i success w odwróconej kolejności dostarczenia | Identyczny wynik po watermark; równe czasy nie tworzą sekwencji |
| Success innego user/host/IP | Brak dopasowania sekwencji |
| Late o 120 s / 120 s + 1 µs | Online / wyłącznie replay; retry nie zmienia tej decyzji |
| Future o 30 s / 30 s + 1 µs | Online / kwarantanna clock-skew; watermark nie skacze |
| Otwarte transakcje ingestion i backlog | Brak przedwczesnej finalizacji; pusty heartbeat zamyka bezczynne okno |
| Spóźniony początek/środek sekwencji | Replay uwzględnia cały potrzebny kontekst i poprawny późniejszy wynik |
| Restart, crash po commit przed ACK, dwóch workerów | Te same match/alert keys, brak zdublowanych outbox effects |
| Zmiana wersji reguły | Rozdzielny stan, stare alerty odtwarzalne z poprzedniej wersji |
| Sigma supported/unsupported, błędne typy i YAML bomb | Poprawny AST albo jawne odrzucenie przed aktywacją |
| New admin: inny target ID i konto o tej samej nazwie | Brak fałszywego połączenia |

Bramka PHASE 4: testy evaluatorów i parsera Sigma oraz integracyjne retry/watermark w prawdziwym PostgreSQL, komplet fixtures ważnych reguł, lint/type checks i dokumentowany pomiar ograniczeń zasobów. Stan PHASE 0 nie spełnia tej bramki.
