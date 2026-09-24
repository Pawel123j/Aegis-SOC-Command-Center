# Risk Engine — deterministyczny projekt v1

**Status: projekt PHASE 0. Algorytm, jego testy i integracja nie są jeszcze zaimplementowane.** Wagi są świadomą polityką demonstracyjną Aegis, nie modelem statystycznym ani prawdopodobieństwem kompromitacji.

## Kontrakt i wzór

Funkcja przyjmuje niezmienny snapshot dowodów, reguł, assetów, reputacji IOC, uprawnień i historii. Zwraca całkowity score `0..100`, komponenty oraz dowody każdego punktu. Wynik nie zależy od bieżącego zegara, kolejności zapytań, retry, losowości ani wywołania zewnętrznego API.

```text
D = max floor(severity_points(rule) * confidence(rule) / 100)
R_raw = D + A + I + C + T + H + P
R = min(100, max(0, R_raw))
```

`D` liczymy po kwalifikujących się sygnałach behawioralnych; maksimum wybiera **jeden istniejący iloczyn** severity/confidence. Nie łączymy najwyższej severity jednej reguły z confidence innej. Pusty zbiór daje `D=0`; remis rozstrzyga logiczny ID. Wszystkie działania są całkowitoliczbowe, `floor` jest wykonywane dokładnie raz na każdym kandydacie D, bez float i bez ukrytego zaokrąglania.

| Składnik | Zakres | Polityka `risk-policy-v1` |
|---|---:|---|
| D — detection | 0–55 | Severity points: informational=5, low=15, medium=30, high=45, critical=55; confidence całkowite 0–100 |
| A — asset criticality | 0–15 | unknown=0, low=0, medium=5, high=10, critical=15; maksimum dla faktycznie dotkniętych assetów |
| I — IOC reputation | 0–15 | Brak/expired/unknown=0; suspicious przy confidence >=50 daje 8; malicious przy confidence >=80 daje 15; pozostałe kombinacje dają 0 |
| C — niezależne sygnały | 0–9 | `min(9, 3 * max(0, n-1))`, gdzie n oznacza zdefiniowane niżej jednostki dowodowe |
| T — szerokość zachowań ATT&CK | 0–6 | `min(6, 2 * max(0, k-1))`, gdzie k to liczba niezależnie potwierdzonych rodzin zachowań z kwalifikującym mappingiem |
| H — previous activity | 0–5 | Co najmniej jeden wcześniejszy, potwierdzony przez analityka incydent tej silnej tożsamości w poprzednich 30 dniach: 5; inaczej 0 |
| P — pre-existing privileges | 0–5 | unknown/standard=0, privileged=3, administrator=5; maksimum dla zaangażowanych kont, według snapshotu sprzed bieżącego łańcucha |

Próg `confidence` dotyczy przyznania I, a nie losowej szansy wykrycia. Reputacja w lokalnej bazie ma mapowanie `severity` → `unknown/suspicious/malicious` zapisane w wersji polityki: informational/low→unknown, medium→suspicious, high/critical→malicious. IOC musi być aktywny i pasować do obserwowanego pola, ze wskazaniem eventu; dowolny IOC w notatce nie zwiększa score. Nie sumujemy reputacji kilku źródeł ani kilku kopii tego samego IOC: bierzemy największą kwalifikującą się wartość I.

IOC-only detection ma wkład D równy zero i nie uczestniczy w C/T; jego informacja jest rozliczana raz w I. Jeśli istnieje niezależna reguła zachowania i pasujący IOC, D opisuje zachowanie, a I jego reputację. Ten wybór zapobiega naliczeniu tej samej reputacji raz jako severity reguły „IOC match”, a drugi raz jako threat intelligence.

## Jednostki dowodowe i ochrona przed podwójnym liczeniem

Score incydentu obliczamy od jego aktualnego zbioru dowodów. **Nigdy nie sumujemy score alertów.** Dodatkowy severity/confidence jednej reguły nie jest ponownie dodawany jako osobny „confidence bonus”.

Każda wersja reguły ma kontrolowaną `risk_signal_family`: `authentication_attack`, `suspicious_execution`, `privilege_change`, `account_change` lub `ioc_only`. Rodzina opisuje predykat, a nie nazwę reguły. Autor nie może zwiększyć score przez utworzenie nowego dowolnego family string.

W ramach rodziny alerty o przecinających się zbiorach event IDs tworzą jedną jednostkę dowodową (spójny komponent grafu overlap). Threshold po user, threshold po IP i sekwencja failures→success nad tymi samymi próbami są zatem jednym sygnałem authentication. Powielona reguła, ponowne dostarczenie, kolejna rewizja evidence lub alias po merge nie tworzą nowej jednostki. Dla n zliczamy wyłącznie jednostki behawioralne posiadające własny predykat i dowody w bieżącym incydencie.

Przy identycznym zestawie dowodów i tym samym predykacie zaklasyfikowanym omyłkowo do dwóch rodzin walidacja reguły/test fixtures musi zgłosić konflikt. Rodziny różne, lecz złożona reguła jedynie dziedziczy wcześniejszy alert bez nowego zachowania, nie kwalifikują się jako nowa jednostka. Np. rule „account compromise” podsumowująca trzy istniejące alerty nie jest czwartym sygnałem. Takie reguły podsumowujące nie są też nowymi kandydatami D: nie podnoszą severity tylko dlatego, że nazwa całego incydentu brzmi groźniej.

`k` zlicza rodziny z co najmniej jedną niezależną jednostką i uzasadnioną techniką ATT&CK. Kilka technik przypisanych do jednej komendy nie daje kilku punktowanych rodzin. Parent/sub-technique oraz kopia tej samej techniki liczą się raz. T jest ograniczonym bonusem za różnorodność zaobserwowanych zachowań, C za liczbę niezależnych sygnałów; wagi obu są jawne i nie dodają ponownie D. Samo dopisanie tagu do wersji reguły bez odpowiadających mu dowodów nie kwalifikuje rodziny do k.

H wyklucza aktualny incydent, jego merge aliases, evidence overlap i ten sam demo/replay run. `subject_start` to najwcześniejszy czas evidence ocenianego alertu albo incydentu. Okno historii to `[subject_start - 30d, subject_start)`, według first_observed historycznych spraw. Wersjonowany verdict `confirmed_malicious` musi być dostępny w zamrożonym cutoff `as_of`; zapisujemy verdict_at/by/version i jego provenance. `Resolved` bez tego verdict nie wystarcza; false positives nigdy nie dają H. Późniejsza korekta verdict nie przepisuje starego obliczenia, lecz wymaga nowego snapshotu. Status analityka nie wynika automatycznie z wysokiego score. Dzięki temu bieżący wynik nie podbija sam siebie przez historię.

P opisuje uprawnienia istniejące **przed** pierwszym eventem bieżącego łańcucha. Eskalacja wykryta w tym łańcuchu nie jest jednocześnie nowym bonusem privileges. Nowy snapshot P wymaga jawnego, uzasadnionego przeliczenia na nową datę oceny, z zachowaniem wcześniejszego wyniku.

## Alert a incydent

Dla pojedynczego alertu zwykle `n=1`, `k<=1`, więc C=T=0; A/I/H/P mogą być dostępne, jeśli istnieją powiązane dowody. Alert ma własny wynik; po dołączeniu do incydentu pokazuje także odrębny incident score. Nie nadpisujemy alert score wartością incydentu i nie przeliczamy incydentu od listy alert scores.

Wynik nie ustanawia stanu incydentu ani automatycznej zgody na containment. Proponowane progi prezentacyjne: 0–24 low, 25–49 medium, 50–74 high, 75–100 critical. `rule.severity`, wyliczony `risk_level` i decyzja analityka o priorytecie są osobnymi polami. Zmiana progów to nowa wersja polityki.

Brak asset inventory, IOC, historii lub informacji o privileges daje 0 w danym komponencie **oraz** `unknown` w completeness; zero nie jest zapewnieniem bezpieczeństwa. Confidence i severity są wymagane w aktywnej regule. Nieznane wartości enum, ujemne liczby lub confidence>100 są błędem walidacji, a nie wartością przycinaną do zakresu.

## Przykłady arytmetyki

| Przypadek | D | A | I | C | T | H | P | Wynik |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Brute force: medium, confidence 80; asset medium; standard account | 24 | 5 | 0 | 0 | 0 | 0 | 0 | 29 |
| Dwa alerty po user/IP z tymi samymi failures; asset high | 24 | 10 | 0 | 0 | 0 | 0 | 0 | 34 |
| IOC-only: malicious 90, asset high, standard account | 0 | 10 | 15 | 0 | 0 | 0 | 0 | 25 |
| Cztery niezależne jednostki i cztery rodziny; critical 80; asset high; malicious IOC 90; potwierdzona historia; istniejący admin | 44 | 10 | 15 | 9 | 6 | 5 | 5 | 94 |
| Maksymalne czynniki przy critical 100 | 55 | 15 | 15 | 9 | 6 | 5 | 5 | 100 (raw 110, cap −10) |

W przykładzie 94: `floor(55*80/100)=44`; `C=min(9,3*(4-1))=9`; `T=min(6,2*(4-1))=6`. Czwarta rodzina wymaga rzeczywistej dodatkowej aktywności, np. utworzenia/dodania konta administracyjnego; sam success po brute force nie stanowi nowej rodziny. Typowy łańcuch authentication → process → privilege ma trzy rodziny, więc nie wolno bez powodu pokazywać k=4. Wartość 94 nie jest zaszyta w scenariuszu ani wymagana dla każdego account compromise.

Gdy dwa istniejące alerty mają critical/confidence 20 i medium/confidence 100, D wynosi `max(11,30)=30`, a nie 55. Gdy usunięta zostanie błędna reputacja IOC, nowa rewizja może obniżyć score; silnik nie wymusza monotonicznego wzrostu ryzyka.

## Explainability, wersje i przeliczenia

Każdy `risk_calculation` jest append-only i zapisuje:

- `subject_type/id`, `subject_revision`, namespace dataset/mode/run oraz `policy_version/hash`.
- `as_of`, event-time interval, wersje źródeł i hashe snapshotów assetów, IOC, privileges i historii.
- Zbiór jednostek sygnałowych, evidence IDs, przypisane rodziny i krawędzie overlap użyte do deduplikacji.
- Zwycięski kandydat D z severity/confidence, źródło A/I/H/P oraz wartości n/k.
- Każdy przyznany i nieprzyznany komponent wraz z przyczyną; sumę raw, clipping i końcowy score.
- Braki kontekstu, actor/trigger przeliczenia i referencję poprzedniej rewizji.

UI odpowiada np.: „+44 critical detection ×80% confidence; +10 asset high; +15 aktywny malicious IOC confidence 90; +9 cztery niezależne sygnały; +6 cztery rodziny z ATT&CK; +5 wcześniejszy potwierdzony incydent; +5 uprawnienia administratora istniejące przed zdarzeniem”. Każdy element prowadzi do danych wejściowych, a brak H wyświetla powód „brak potwierdzonej historii” albo „history unknown”.

Aktualizacja IOC, poprawa asset inventory, merge, odłączenie błędnego evidence, rozstrzygnięcie false positive lub zmiana polityki tworzą nowe obliczenie. Nie modyfikują dawnych komponentów. Ponowne przeliczenie identycznego subject revision, policy i snapshotów zwraca istniejący wynik przez klucz UNIQUE. Zapis nowego score i outbox jest jedną transakcją; retry nie tworzy serii identycznych wpisów.

Replay używa zamrożonych kontekstów opisanych w manifeście. Jeśli historyczny snapshot nie istnieje, wynik zostaje opisany `context_as_of_replay` zamiast udawać ocenę z czasu zdarzenia. Metryki live i demo pozostają oddzielne. Historyczne oceny są odtwarzalne tak długo, jak zachowane są wskazane snapshoty i dowody zgodnie z polityką retencji.

## Plan testów i bramka PHASE 9

Testy golden vectors obejmą każdą komórkę tabeli wag, granice confidence 49/50/79/80, granice poziomów prezentacyjnych, wszystkie powyższe przykłady, overflow raw>100 oraz brak kontekstu. Property tests sprawdzą zakres `0..100`, niezależność od kolejności wejścia, niezmienność przy duplicate delivery i brak wzrostu przy dodaniu aliasu/tej samej reputacji.

Testy integracyjne wymagają: zmiany IOC powodującej nową rewizję i czytelny delta, zgodnego score po replay tych samych snapshotów, poprawnego przeliczenia po merge/unlink, konkurencyjnych zadań z jednym wynikiem oraz braku dodatniej pętli historycznej. Specjalne fixture obejmie dwa pokrywające się brute-force alerts i sekwencję nad tymi samymi failures: n nadal równa się 1.

Bramka fazy: brak niewyjaśnionych punktów, deterministyczne wyniki dla tych samych danych, zgodna odpowiedź API i UI, testy jednostkowe oraz integracyjne PostgreSQL, lint/type checks. Kalibracja wag wymaga osobnego zbioru scenariuszy i jawnego przeglądu false positives; wysoki score nie potwierdza skuteczności detekcji bez takiej walidacji.
