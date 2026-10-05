# Risk Engine — wersjonowana ocena i kontekst IOC

Data: 2026-10-03. Stan: Etap 3 wdrożony; automatyczna walidacja zaliczona.
[Decyzja](adr/0009-explainable-risk.md) zastępuje dawny projekt PHASE 0.
Wynik jest jawnym priorytetem według polityki Aegis, nie statystycznym
prawdopodobieństwem kompromitacji. Severity detekcji, risk i decyzja analityka
o stanie incydentu są odrębnymi informacjami.
Aktualizacja 2026-10-05: Etap 7 dodaje opt-in risk-policy-v4 dla lokalnych IOC;
jego końcową regresję i lokalne wdrożenie opisuje [raport](validation-intelligence.md).

## Polityka risk-policy-v3 i historia v2

Etap 5 rozwija kontrakt wejścia przez osobne `severity_baselines` Sigma.
Wagi i arytmetyka kontrolowanych sygnałów opisanych niżej pozostają zachowane.
Zweryfikowana utrwalona rewizja Sigma daje wyłącznie bazowy wkład D z własnej
severity; nie nadaje confidence ani rodziny zachowania. Przy samej Sigma C/E
mają zero punktów i status unknown. Przy mieszanych źródłach C/E liczą tylko
dotychczasowe kontrolowane sygnały, bez premii za kolejną nazwę reguły.
Obliczenia bez kontekstu IOC i baseline TI zachowują wersję/hash v3.
Zapisane v2 nadal zwracają swój oryginalny
snapshot i hash, bez przeliczenia przy GET. [ADR 0011](adr/0011-versioned-sigma-rules.md),
[walidacja Sigma](validation-sigma.md).

## Polityka risk-policy-v4 — Etap 7

V4 zachowuje arytmetykę kontrolowanych zachowań v3 i dodaje osobny wkład I
z utrwalonych lokalnych dopasowań IOC. Builder sprawdza oryginalny raw/normalized
event, zakres, receipt, rewizję oraz hash. Reputacja i confidence IOC są
deklaracją źródła; confidence samej detekcji pozostaje nieznany.

| Kwalifikujący IOC | Punkty I |
| --- | ---: |
| Malicious, confidence ≥80 | 15 |
| Malicious, confidence niższy albo nieznany | 5 |
| Suspicious, confidence ≥50 | 8 |
| Suspicious niższy albo nieznany; clean/unknown | 0 |

I wybiera maksimum, nigdy sumę, do 15. Fakty wymagają kwalifikujących się
event references, zgodnej tożsamości subject i ważności; clean nie odejmuje
punktów i nie potwierdza bezpieczeństwa. Produkcyjny builder wybiera najwyżej
100 najsilniejszych field matches, podając available/selected/truncated
i porządek wyboru; zachowuje dokładne maksimum I.

Medium alert `ti:malicious-indicator` daje D30 z oryginalnego dopasowania,
bez kontrolowanej rodziny zachowania. Sam TI daje C/E0; dodatkowe nazwy IOC
ani kilka pól tego samego eventu nie zwiększają tych składników. Przykład
samego TI: malicious z confidence 80 daje 30+15=45; nieznany confidence
daje 30+5=35. Oba wyniki są priorytetem analizy, bez potwierdzenia ataku.
T nadal wymaga osobnych potwierdzonych zachowań; TI nie nadaje technik MITRE.

Production bez kontekstu IOC i baseline TI nadal używa niezmienionego v3.
V2/v3 wejścia, hashe i dawne wyniki pozostają zachowane; GET nie przelicza ich.
Import albo PATCH IOC nie zmieniają pierwszych dopasowań ani istniejących ocen.
Backfill TI indeksuje tylko events bez receipt; późniejsze jawne
risk/recalculate może użyć tych dopasowań i zapisać kolejną wersję oceny.
[Pełny kontrakt](intelligence.md), [ADR 0013](adr/0013-local-intelligence.md).

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
| I — reputacja IOC | 15 | V4: suspicious z confidence co najmniej 50: 8; malicious co najmniej 80: 15, niższe/nieznane: 5; maksimum. V3 zachowuje dawną arytmetykę |
| T — różnorodność potwierdzonych zachowań | 6 | ograniczony bonus z wersjonowanych mappings i niezależnych dowodów; sam tag nie wystarcza |
| H — potwierdzona wcześniejsza aktywność | 5 | wcześniejszy confirmed_malicious tej silnej tożsamości w 30 dniach, z pominięciem własnej sprawy, overlap i tego samego replay run |
| P — uprzednie uprawnienia | 5 | standard 0, privileged 3, administrator 5; udokumentowane przed pierwszym dowodem |

Poziomy użytkownika: **0–29 low, 30–59 medium, 60–79 high, 80–100 critical**.
Zmiana progów, wag lub deduplikacji wymaga nowej wersji polityki i hasha.

## Bieżące źródła i braki

Produkcja korzysta z oryginalnych, zweryfikowanych dowodów alertów i
kontrolowanego katalogu reguł. Nie pobiera reputacji z Internetu i nie uznaje
arbitralnego `extensions.risk`, notatki ani nazwy administratora za zaufany fakt.
Confidence detekcji i A/U/T/H/P pozostają **unknown** do uruchomienia ich
prawdziwych źródeł. I może korzystać z lokalnych, wersjonowanych deklaracji IOC
Etapu 7; brak tego kontekstu pozostaje unknown. Zero punktów nie zapewnia bezpieczeństwa.
Jawny czysty test może sprawdzić wersjonowane wejścia kontekstowe w symulacji.

Rodziny zachowań są kontrolowane. Alerty tej samej rodziny z przecinającymi się
event IDs stanowią jedną jednostkę. Złożona reguła używa dowodów swoich etapów;
nie dodaje jednostki za sam tytuł podsumowania. E liczy każdy event ID
kwalifikującego się sygnału tylko raz; niepowiązane wejście nie daje punktów.
Sam dowolny kontekst IOC bez kwalifikującego się zachowania lub zweryfikowanego
baseline nie tworzy oceny. Etap 7 dopuszcza oryginalny medium TI baseline,
z jawnym brakiem C/E premii za niezależne zachowania.
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
Bez kontekstu IOC i przyszłych źródeł maksimum punktacji v3 wynosi
55+9+12=76. Kwalifikujący się IOC w v4 może dodać najwyżej 15.

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
GET policy opisuje v4 wraz z production_default_policy_version v3 i jego hashem.
Jawna symulacja wybiera v4 dla wejścia TI/IOC, inaczej zachowuje v3.

Panel przedstawia aktualny wynik, wkłady, nieznane dane i wcześniejsze oceny.
Pierwszy wynik albo brak oceny są wyraźne; zero nie jest zastępowane pustą
wartością. Szczegółowe wyniki i granice dowodu opisuje
[raport Etapu 3](validation-risk.md).

Etap 6 wyświetla na profilu encji maksimum aktualnych kwalifikujących się ocen
alertów w wybranym oknie, wraz z istniejącym calculation ID i wyjaśnieniem.
Nie dodaje entity scoring ani nowej wersji polityki. False positive nie
uczestniczy w tej projekcji; brak oceny daje null. Obserwowana nazwa, SID,
host lub IP nie stają się zweryfikowaną krytycznością/privilege context.
[Profile i zakres](entities.md), [ADR 0012](adr/0012-observed-entity-profiles.md).
