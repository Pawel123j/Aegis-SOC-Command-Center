# Risk Engine — Etap 3

Data: 2026-10-03. Stan: Etap 3 wdrożony; automatyczna walidacja zaliczona.
[Decyzja](adr/0009-explainable-risk.md) zastępuje dawny projekt PHASE 0.
Wynik jest jawnym priorytetem według polityki Aegis, nie statystycznym
prawdopodobieństwem kompromitacji. Severity detekcji, risk i decyzja analityka
o stanie incydentu są odrębnymi informacjami.

## Polityka risk-policy-v3 i historia v2

Etap 5 rozwija kontrakt wejścia przez osobne `severity_baselines` Sigma.
Wagi i arytmetyka kontrolowanych sygnałów opisanych niżej pozostają zachowane.
Zweryfikowana utrwalona rewizja Sigma daje wyłącznie bazowy wkład D z własnej
severity; nie nadaje confidence ani rodziny zachowania. Przy samej Sigma C/E
mają zero punktów i status unknown. Przy mieszanych źródłach C/E liczą tylko
dotychczasowe kontrolowane sygnały, bez premii za kolejną nazwę reguły.
Nowe obliczenia mają wersję/hash v3. Zapisane v2 nadal zwracają swój oryginalny
snapshot i hash, bez przeliczenia przy GET. [ADR 0011](adr/0011-versioned-sigma-rules.md),
[walidacja Sigma](validation-sigma.md).

Wszystkie operacje są całkowitoliczbowe. Kolejność wejścia, retry, nazwa nowego
alertu oraz bieżący zegar nie zwiększają wyniku.

```text
D = max severity_points(signal), gdy confidence nieznane
D = max floor(severity_points(signal)*confidence(signal)/100), gdy udokumentowane
D = max powyższych kandydatów oraz severity_points(verified Sigma baseline)
C = min(9,3*max(0,independent_units-1))
E = min(12,2*max(0,unique_controlled_signal_events-1))
raw = D+C+E+A+U+I+T+H+P
score = min(100,raw)
clipping = score-raw
```

D wybiera jedną istniejącą parę severity/confidence; przy mieszanych danych
każdy kandydat stosuje własne confidence albo jawny severity-only baseline.
Brak confidence nie jest zastępowany 100%. Puste kwalifikujące się dowody dają
zero i not_applicable, a rekord bez obliczenia nadal pokazuje null.

| Składnik | Maksimum | Zasada |
| --- | ---: | --- |
| D — detekcja | 55 | informational 5, low 15, medium 30, high 45, critical 55; udokumentowane confidence skaluje własną wagę |
| C — niezależne sygnały | 9 | 3 za każdą jednostkę poza pierwszą; overlap tej samej rodziny scala się przechodnio |
| E — zdarzenia dowodowe | 12 | 2 za każde unikalne zdarzenie kontrolowanego sygnału poza pierwszym; Sigma baseline nie zwiększa E |
| A — znaczenie hosta | 15 | low 0, medium 5, high 10, critical 15; maksimum z powiązanego kontekstu |
| U — znaczenie konta | 10 | low 0, medium 3, high 6, critical 10; maksimum |
| I — reputacja IOC | 15 | aktywne suspicious z confidence co najmniej 50: 8; malicious co najmniej 80: 15; maksimum |
| T — różnorodność potwierdzonych zachowań | 6 | ograniczony bonus z wersjonowanych mappings i niezależnych dowodów; sam tag nie wystarcza |
| H — potwierdzona wcześniejsza aktywność | 5 | wcześniejszy confirmed_malicious tej silnej tożsamości w 30 dniach, z pominięciem własnej sprawy, overlap i tego samego replay run |
| P — uprzednie uprawnienia | 5 | standard 0, privileged 3, administrator 5; udokumentowane przed pierwszym dowodem |

Poziomy użytkownika: **0–29 low, 30–59 medium, 60–79 high, 80–100 critical**.
Zmiana progów, wag lub deduplikacji wymaga nowej wersji polityki i hasha.

## Bieżące źródła i braki

Produkcja korzysta z oryginalnych, zweryfikowanych dowodów alertów i
kontrolowanego katalogu reguł. Nie pobiera reputacji z Internetu i nie uznaje
arbitralnego `extensions.risk`, notatki ani nazwy administratora za zaufany fakt.
Confidence i A/U/I/T/H/P pozostają **unknown** do uruchomienia ich prawdziwych
źródeł w następnych etapach. Ich zero punktów nie zapewnia bezpieczeństwa.
Jawny czysty test może sprawdzić wersjonowane wejścia kontekstowe w symulacji.

Rodziny zachowań są kontrolowane. Alerty tej samej rodziny z przecinającymi się
event IDs stanowią jedną jednostkę. Złożona reguła używa dowodów swoich etapów;
nie dodaje jednostki za sam tytuł podsumowania. E liczy każdy event ID
kwalifikującego się sygnału tylko raz; niepowiązane wejście nie daje punktów.
W tym etapie sam IOC bez kwalifikującego się zachowania nie tworzy oceny;
IOC-only wymaga jawnego rozwinięcia polityki wraz z Threat Intelligence.
Incydent nie sumuje scores alertów. Ocenia aktywne dowody, pomijając alerts
false_positive; resolved pozostaje dowodem. Odpięcie lub korekta może obniżyć
wynik. Ręczna severity sprawy, notatka i przypisanie nie zmieniają detekcji.

Przykłady bez przyszłego kontekstu i bez confidence:

| Dane | D | C | E | Wynik |
| --- | ---: | ---: | ---: | --- |
| Pojedyncza detekcja high, jeden event | 45 | 0 | 0 | 45 medium |
| Pięć porażek medium, jedna rodzina | 30 | 0 | 8 | 38 medium |
| Pięć porażek → sukces high | 45 | 0 | 10 | 55 medium |
| Pełny ciąg dziewięciu eventów, critical, trzy rodziny | 55 | 6 | 12 | 73 high |

Drugi alert nad tymi samymi porażkami nie dodaje jednostki ani eventów.
Sam wynik 73 nie oznacza potwierdzonego ataku.
Bez przyszłych źródeł kontekstu maksimum bieżącej punktacji wynosi
55+9+12=76. Nie podbijamy go do Critical tylko dla efektu demonstracyjnego.

## Utrwalanie i historia

Snapshot obliczenia zawiera subject/revision, datę i trigger, poprzedni wynik,
wersję/hash polityki, wejście i jego hash, wybrane jednostki i event IDs,
punkty wraz z powodami, raw/clipping/score, brakujący kontekst i wykluczone alerts.
Wyniki są append-only. Bieżący score wskazuje konkretne obliczenie;
nie nadpisuje score źródłowego alertu wynikiem całego incydentu.
Read API nie zapisuje stanu. Identyczne wejście nie tworzy kopii wyniku.
Nowy alert, obliczenie, automatyczna sprawa i audyt są atomowe.
Funkcja PostgreSQL chroni zakres, head i odniesienia do dowodów;
arytmetyka jest zadaniem zaufanego modułu aplikacji. Append-only chroni
dotychczasowe wpisy, a nie autentyczność nowego INSERT po przejęciu runtime.

W przypadku replay dane i zakres są jawne; późniejsze konteksty nie
przepisują dawnych wyników. Produkcyjny kalkulator bieżącego etapu nie
korzysta z zewnętrznej historii ani z mutable deployments do oceniania
oryginalnych dowodów.

## API i panel

Pod `/api/v1`: GET `/risk/policy`, GET `/alerts/{id}/risk`,
GET `/incidents/{id}/risk`; historia ma limit 1–50 (domyślnie 10)
i jawne `history_truncated`. Szczegóły alertu/sprawy zawierają
`risk_explanation`, a listy score, level i calculation ID.
POST `/risk/backfill` ma ograniczoną porcję starszych rekordów i wymaga
administracyjnego uprawnienia. Czysty POST `/risk/test` sprawdza wejście
w symulacji, bez zapisu alertów i spraw.
POST `/alerts/{id}/risk/recalculate` i `/incidents/{id}/risk/recalculate`
wymagają właściwego manage/edit oraz If-Match. Ponowna ocena nie zmienia
wersji decyzji analityka; identyczne wejście zwraca dotychczasowy wynik.

Panel przedstawia aktualny wynik, wkłady, nieznane dane i wcześniejsze oceny.
Pierwszy wynik albo brak oceny są wyraźne; zero nie jest zastępowane pustą
wartością. Szczegółowe wyniki i granice dowodu opisuje
[raport Etapu 3](validation-risk.md).
