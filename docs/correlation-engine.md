# Correlation Engine — Etap 2 i dalszy projekt

Etap 2 dodaje natywne reguły threshold/sequence, trwały proces korelacji,
wielozdarzeniowe alerty i dowody oraz ich integrację z incydentami.
Aktualną finalizację, tożsamości, izolację i granice zakresu opisuje
[ADR 0008](adr/0008-temporal-correlation.md). Wykonane kontrole i szczegółowy
kontrakt przyrostu opisuje [raport Etapu 2](validation-correlation.md).

## Działające reguły Etapu 2

| Reguła | Warunek i okno | Severity |
| --- | --- | --- |
| `possible_bruteforce_compromise` | 5 porażek, potem sukces tego samego użytkownika/hosta/IP w 10 min | High |
| `repeated_authentication_failures` | 5 porażek tego samego użytkownika/hosta/IP w 5 min | Medium |
| `powershell_then_outbound` | PowerShell, potem wychodzące połączenie tego samego trwałego procesu/hosta w 5 min | High |
| `login_then_local_admin_change` | Sukces logowania, potem dodanie członka lokalnej grupy administratorów przez tego użytkownika na tym hoście w 10 min | High |
| `possible_multi_stage_compromise` | 5 porażek → sukces → PowerShell → zmiana grupy → połączenie wychodzące, użytkownik/host i pełny span 30 min; PowerShell/network wymaga tego samego procesu | Critical |

W panelu wybierz **Reguły detekcji → Korelacja**. Szczegóły pokazują wersję,
liczność etapów, AND/OR, okno, wspólne encje i wskazówki analityczne.
Admin/Manager może zmienić enabled z kontrolą wersji; Analyst może wykonać
izolowany test maksymalnie 100 normalized events. Test działa także dla
wyłączonej reguły i nie tworzy alertów, spraw ani checkpointów.
Viewer odczytuje katalog i stan pokrycia.

Alert pokazuje chronologiczną listę wszystkich zdarzeń wybranych do dowodu.
Każdy otwiera oryginalny normalized/raw snapshot oraz SHA-256. Incydent agreguje
czas, źródła i encje całego dowodu. Pojedynczy High/Critical alert nadal tworzy
własną sprawę; reguła wieloetapowa nie scala istniejących spraw analityka.
Zmiana grupy dowodzi wykonania operacji przez aktora, nie automatycznie nadania
uprawnień właśnie temu aktorowi. Kolejność zdarzeń stanowi potencjalny ciąg
aktywności wymagający oceny, a nie dowód związku przyczynowego.

## Praca, finalizacja i limity

`app.correlator` odpytuje PostgreSQL co 2 s, odkrywając i oceniając do 25 zadań
w przebiegu. `AEGIS_CORRELATION_POLL_SECONDS` i `AEGIS_CORRELATION_BATCH_SIZE`
mają walidowane granice. Restart korzysta z trwałego stanu oraz klucza
deduplikacji, a alert/audyt/automatyczna sprawa/checkpoint mają wspólny commit.
Nie zależy to od dostępności wyszukiwarki ClickHouse.

Live finalizuje po buforze 120 s i opróżnieniu zaległości. Znacznik przyszłego
czasu ponad 30 s względem przyjęcia daje `clock_skew`, zbyt spóźniony log daje
`late`. Log pozostaje w archiwum. Zamknięty replay pomija te granice zegara live
i korzysta z immutable manifestu wejścia oraz snapshotu deploymentów.
API finalizacji wymaga dokładnego dataset/run i oczekiwanej liczby wejścia;
nie tworzy źródła ani generatora. Publiczne źródła nadal mają tryb live.

Maksymalnie 500 kandydatów encji/okna i 100 dowodów na alert. Przekroczenie
kandydatów zapisuje końcowe `incomplete`, bez alertu z obciętych logów i bez
automatycznego retry. Stan pokrycia ujawnia te wyniki, backlog, watermark oraz
niepełną listę zakresów. Dowód jest minimalnym zbiorem spełniającym etapy;
kolejne kwalifikujące się kotwice mogą dawać kolejne alerty. Nie dodano suppression.
Sekwencja wymaga ściśle rosnącego czasu między etapami; zdarzenia o równym
czasie mogą zwiększyć licznik jednego etapu.

Źródło musi dostarczyć wiarygodne `host.id` i `process.entity_id`, jeśli reguła
ich wymaga. Hostname zastępczy ma zakres źródła; sam PID lub IP nie zastępuje
tożsamości. Rozpoznawanie aliasów i rejestr encji to dalsze etapy.
Explorer nie ma jeszcze filtrów adnotacji correlation rule/MITRE.

## Historyczny projekt szerszego silnika

**Poniżej zachowano historyczny projekt PHASE 0.** Graf, storyline,
automatyczny merge i reconstruct pozostają przyszłym zakresem. Opisane
poniżej statusy i dokładny dataset isolation nie zastępują aktualnego kontraktu
incydentów z [ADR 0007](adr/0007-incident-case-management.md).

## Cel i wejście

Korelacja łączy powiązane zachowania w jeden potencjalny incydent, zachowując każdą regułę, dowód i decyzję powiązania. Przyjmuje finalne dopasowania detekcji i wersjonowane rewizje alertów. Jej wyjściem jest propozycja/aktualizacja incydentu, graf dowodów, storyline i polecenie przeliczenia ryzyka. Zapis incydentu oraz outbox następuje w jednej transakcji PostgreSQL.

Wszystko jest odseparowane przez `(dataset_id, mode, run_id)`. Demo/replay nigdy nie łączy się z live. Wspólne definicje czasu, watermark, deduplikacji i wersji znajdują się w [kontrakcie detekcji](detection-engine.md). Kolejność źródłowa to event-time, nie czas uruchomienia workera ani kliknięcia scenariusza demo.

## Tożsamości i siła krawędzi

Resolver encji ma wersję i jawne pochodzenie każdej relacji. `principal_key` to stabilne ID użytkownika wraz z realm/domain; konto lokalne ma dodatkowo zakres hosta. `host_key` preferuje zarejestrowany identyfikator hosta; hostname jest bezpiecznym zastępstwem tylko w jednoznacznej, wersjonowanej mapie źródła. Nazwa `admin` na dwóch maszynach nie oznacza tej samej osoby.

| Sygnał | Automatyczne łączenie? | Reguła |
|---|---|---|
| Ten sam stabilny session/logon ID na tym samym hoście, principal zgodny | Tak | Session ID musi mieć zakres hosta/boot/provider; nie jest globalnym numerem |
| Ten sam principal + host oraz jawny, pasujący krok łańcucha | Warunkowo | Różne znane session IDs blokują połączenie; konto shared/service wymaga session albo innego silnego dowodu |
| Failure → success z tym samym principal, destination host i source IP | Tak | Tylko według dokładnej sekwencji detekcji; IP jest tu dodatkowym ograniczeniem |
| Process parent/child z trwałymi process entity IDs i hostem | Tak | PID sam nie wystarcza z powodu ponownego użycia |
| Ten sam source IP, subnet, ASN lub IOC | Nie | NAT, proxy i wspólna infrastruktura; może powstać wyłącznie `related_to` |
| Ten sam host bez tożsamości/session/process | Nie | Wspólne jump hosty i serwery obsługują wielu użytkowników |
| Ten sam MITRE technique/tactic albo rule ID | Nie | Pomaga opisać historię; nie dowodzi wspólnego sprawcy |
| To samo display name/username bez realm | Nie | Niejednoznaczna tożsamość zostaje jawnie oznaczona |

Brak wymaganej silnej tożsamości daje samodzielny alert lub osobny kandydat incydentu. Nie zastępujemy brakującego user przez IP. Reguła brute-force po IP, obejmująca wielu użytkowników, nie przenosi automatycznie całego zbioru prób do incydentu jednego konta. Można dołączyć właściwy podzbiór dowodów do sekwencji konkretnego konta; pierwotny alert zachowuje pełny zakres i relację kontekstową.

## Jawne reguły łańcucha

`account_compromise_v1` rozpoznaje opcjonalne etapy:

```text
authentication failures → success for the same identity
                        → suspicious process in that host/session
                        → suspicious privilege change in that host/session
```

Nie wymagamy wszystkich etapów, aby zachować podejrzane zachowanie. Sam threshold brute force tworzy kandydat `Brute Force`; powiązany sukces może zmienić tytuł na `Possible Account Compromise`, z audytem i zachowaniem pierwotnej przyczyny. Późniejszy PowerShell nie jest potwierdzeniem przejęcia konta sam w sobie. Wersja reguły zawiera dozwolone przejścia, wymagane klucze tożsamości, maksymalne odstępy i uzasadnienie.

Tylko predykaty wskazane w wersji correlation rule mogą łączyć pary etapów. Zwykłe auth → dowolny process nie wystarcza; proces musi być osobnym dopasowaniem podejrzanej aktywności. Podobieństwo technik pełni rolę opisową po ustaleniu silnego związku.

Maksymalny span całego automatycznie połączonego komponentu to **30 min event-time**: `max(evidence.timestamp) - min(evidence.timestamp) <= 30m`. Warunek dotyczy całego zbioru, nie tylko każdej sąsiedniej pary. Łańcuch co 29 min nie może rosnąć przez całą dobę. Początek i koniec wyznaczają dowody, nie czas ostatniej notatki analityka. Alerty z dłuższym zagregowanym evidence mogą udostępnić konkretny match/wycinek dowodów, z jego jawnymi referencjami; nie zmieniamy zakresu źródłowego alertu.

Przekroczenie okna, sprzeczna session lub niezgodne silne tożsamości tworzą nowego kandydata oraz ewentualną relację `related_to` z powodem. Przejście na inny host wymaga odrębnej reguły lateral movement z silnymi dowodami; samo to samo konto na dwóch hostach nie jest taką regułą.

## Determinizm i transakcje

Orkiestrator korelacji przetwarza finalne matches w porządku `(anchor_timestamp, logical_match_id)`. Checkpoint detekcji potwierdza, że dla danego zakresu wszystkie wyniki zostały zapisane przed awansem checkpointu korelacji. Fizyczne dostarczenie z Celery może być wielokrotne i w dowolnej kolejności; worker pobiera pracę z trwałego inboxu według checkpointu.

Pierwsza implementacja stosuje krótki **transaction advisory lock** PostgreSQL na namespace dataset/run podczas mutacji korelacji. Ogranicza to równoległość jednego datasetu, lecz zapobiega sytuacji, gdy dwóch workerów widzi „brak incydentu” i jednocześnie tworzy dwa. Po blokadzie kandydaci są ponownie odczytywani z `SELECT ... FOR UPDATE` w stałym porządku ID. Blokady transakcyjne zwalniają się po końcu transakcji; ich użycie musi być spójne we wszystkich ścieżkach aplikacji. Są to właściwości opisane w [dokumentacji PostgreSQL](https://www.postgresql.org/docs/17/explicit-locking.html). Drobniejszy podział blokad wymaga późniejszego ADR i testów wyścigów.

Transakcja:

1. Blokuje namespace, sprawdza unikalny klucz przetworzenia `(correlation_rule_version, match_id, evidence_revision)`.
2. Pobiera kandydatów w zakresie czasu i tożsamości oraz ich aktualne statusy.
3. Ocenia jawne krawędzie, konflikt tożsamości i pełny span proponowanego komponentu.
4. Tworzy kandydata, dołącza dowody albo scala zgodnych kandydatów.
5. Zapisuje rewizję grafu, powody decyzji, membership, audyt, risk recalculation i outbox; przesuwa checkpoint.
6. Commit jest podstawą ACK. Crash po commit przed ACK nie powoduje drugiego skutku.

Jeśli kilka kandydatów jest zgodnych, survivor jest wybierany leksykograficznie po `(earliest_evidence_time, seed_logical_match_id, incident_id)`. Seed i ID nowego incydentu pochodzą z deterministycznego namespace oraz pierwszego match. Połączenie zawsze ponownie sprawdza tożsamości i span **sumy** komponentów. Jeżeli wszystkie razem nie spełniają ograniczeń, kandydaci są rozpatrywani w tej samej kolejności; nie arbitralnie według kolejności rekordów SQL. Odrzucone połączenia dostają powód.

Źródłowe incydenty po merge pozostają jako redirect/alias do survivora. Nie usuwamy notatek, evidence ani poprzednich ID. Audyt przechowuje źródła, cel, actor/service, correlation version, powody, membership przed/po, czas zdarzeń i czas operacji. Konflikt właścicieli lub statusów analitycznych wstrzymuje automatyczny merge i tworzy propozycję do rozstrzygnięcia. Unikalność membership oraz klucz operacji chronią przed ponownym dodaniem tego samego match.

`Resolved` i `False Positive` są stanami zamkniętymi: nowe dopasowanie nie otwiera ich automatycznie. Powstaje nowy kandydat z `related_to` i przyczyną powiązania. Wznowienie jest osobną, uprawnioną decyzją analityka. Zmiana membership po pracy analityka musi zachować wszystkie wcześniejsze rewizje; brak cichych zmian owner/status. `Contained` nie oznacza zamkniętego incydentu, lecz nowe dowody nadal podlegają ograniczeniom okna i tożsamości.

## Storyline i dowody

Storyline jest deterministyczną projekcją wersji grafu. Wiersze są sortowane po event-time i ID, a współdzielone eventy pokazujemy raz. Zdania powstają z kontrolowanych szablonów faktów; generatywna AI nie jest zależnością. Każdy wiersz zawiera liczbę unikalnych eventów, interval, principal/host/session, link do alertu, wersję reguły, confidence i evidence IDs. UI pokazuje „suspected”/„possible”, gdy taki jest poziom dowodów.

Przykładowa historia, do uzyskania z rzeczywistego pipeline w późniejszym demo:

| Event-time | Fakt | Wyjaśnienie powiązania |
|---|---|---|
| 14:03–14:04 | 27 failures dla realm/alice na host h17 | Unikalne source event IDs, próg threshold |
| 14:05 | Success dla realm/alice z tego samego source IP | Ten sam principal i host, sekwencja failures→success |
| 14:07 | Podejrzana komenda PowerShell | Ten sam session/host, osobna reguła procesu |
| 14:09 | Podejrzane dodanie realm/alice do lokalnej grupy administratorów | Actor principal, session i host zgodne z poprzednimi etapami; konto docelowe zapisane osobno |

Powyższy łańcuch dotyczy hosta Windows. Linux może mieć osobny łańcuch z podejrzanym shellem/sudo; nazwa użytkownika wspólna dla obu platform nie wystarcza do scalenia. Nie fabrykujemy technik dla estetycznej osi czasu. [T1548.003](https://attack.mitre.org/techniques/T1548/003/) opisuje sudo/sudo caching, a [T1068](https://attack.mitre.org/techniques/T1068/) wymaga przesłanki exploitacji podatności. Lista ATT&CK w incydencie zachowuje mapping poszczególnych reguł i jego uzasadnienie.

Ryzyko jest liczone od zbioru dowodów i aktualnej rewizji membership, zgodnie z [risk engine](risk-engine.md). Nie sumujemy score alertów i nie zwiększamy go za duplikat, merge alias lub samą zmianę tekstu storyline.

## Replay, limity i weryfikacja

Replay jest izolowanym namespace, z zamkniętym zbiorem wejścia i snapshotem wersji. Tryb `reanalysis` dla `[a,b)` pobiera także alerty z `[a-30m,a)` oraz `[b,b+30m)`; jest deterministyczny dla tego manifestu, ale nie obiecuje membership identycznego z live. Przykład: auth A w 0 min, process B w 20 min i privilege C w 40 min daje w pełnym przebiegu A+B oraz osobno C (span 40 min przekracza limit). Reanaliza od 40 min z halo od 10 min nie widzi A i może połączyć B+C. Samo stałe halo nie rozwiązuje tego problemu.

Tryb `reconstruct` wymaga kompletnego checkpointu członkostwa, stanów operatora i aktywnych komponentów na granicy początkowej oraz wszystkich późniejszych eventów/komend, albo pełnego replay od ustalonej granicy resetu. Bez tych danych API odrzuca żądanie dokładnej rekonstrukcji zamiast obiecywać równoważność. Brak halo/stanu jest widoczny jako `incomplete_context`; reanaliza może trafić do nowej investigation po jawnej ocenie, nigdy nadpisać live grafu. Zamknięte demo zaczyna od pustego stanu i znanej granicy resetu, więc pozostaje powtarzalne. Jednoczesne przejęcie całej historii bez limitu jest zabronione. Replay nie modyfikuje owner/status żywych incydentów ani live SOC metrics.

Wyszukiwanie kandydatów wymaga indeksów PostgreSQL po namespace, silnych encjach i przedziale czasu. Limit kandydatów lub evidence nie uprawnia do obcięcia wejścia i oznaczenia wyniku jako pełnego: zadanie zostaje odłożone/backpressure, a analityk widzi `correlation_incomplete`. Same podobne techniki i IP nie zwiększają przestrzeni automatycznych kandydatów.

Wymagane testy PHASE 6:

- Pełny, poprawnie opisany łańcuch → jeden incydent, komplet dowodów i stabilna storyline.
- Ten sam NAT, różni users; ten sam jump host, różne sessions; ten sam MITRE → oddzielne incydenty.
- Niejednoznaczne nazwy użytkowników, recycled PID i session ID z innego boot → brak silnej krawędzi.
- Skrajne granice 30 min, oraz A→B i B→C po 20 min → brak komponentu 40-minutowego.
- Wszystkie permutacje kolejności dostarczenia → ten sam logiczny graf i risk inputs po finalizacji.
- Dwa równoległe create/merge, crash po commit i retry → jeden survivor, jeden zestaw membership, pełny audyt.
- Konflikt owner/status → jawna propozycja, bez utraty pracy analityka.
- Nowy alert po `Resolved`/`False Positive` → nowy kandydat, brak automatycznego reopen.
- Rewizja evidence i późniejszy replay → zachowana historia i brak live mutation.
- Brak danych w halo oraz limit kandydatów → jawne `incomplete`, bez pozornej pełnej korelacji.
- A@0/B@20/C@40: lokalna reanaliza może mieć inny membership; reconstruct z pełnym checkpointem odtwarza live wynik.

Bramka akceptacji wymaga testów integracyjnych z równoległymi transakcjami PostgreSQL, a nie tylko mocków repozytorium. Wyniki deterministyczne dotyczą identycznego manifestu wejścia, wersji reguł/resolvera i snapshotu konfiguracji.
