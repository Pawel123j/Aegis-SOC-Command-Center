# Etap 5 — import i wykonanie reguł Sigma

Punkt wyjścia: Etap 4, commit `64f837a`. Data rozpoczęcia: 2026-10-03.
Stan: Etap 5 wdrożony i zweryfikowany automatycznie; wynik i granice odbioru opisuje
[raport Etapu 5](validation-sigma.md).

## Zakres i decyzje

Import pojedynczej definicji YAML, walidacja, bezstanowy test na zdarzeniach
znormalizowanych, wersjonowane przechowywanie i jawne włączenie przez uprawnioną
osobę. Reguła działa w istniejącym detektorze; jej alert korzysta z audytu,
historii ryzyka, mapowania MITRE oraz automatycznego incydentu.
To rozszerzalny podzbiór, opisany przez `/api/v1/sigma/capabilities`.
Punktem odniesienia jest [specyfikacja Sigma 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
Nie deklarujemy zgodności z całą specyfikacją ani obsługi wszystkich reguł
z publicznych repozytoriów. [ADR 0011](adr/0011-versioned-sigma-rules.md)
opisuje granice dowodu i zgodność historii.

## Audyt punktu wyjścia

Istniejące trzy reguły pojedynczych zdarzeń, trwałe joby detekcji i pięć reguł
korelacji miały kontrolowane, niezmienne definicje. Wdrożenie reguły miało
identyfikator, wersję i optimistic concurrency, ale aplikacja nie importowała
YAML ani dowolnego AST. Alert odwołuje się do wdrożenia i przechowuje snapshot.
Ocena `risk-policy-v2` rozpoznaje cztery kontrolowane rodziny zachowań.
MITRE ma przypięty katalog i osobne historyczne mapowania.

Rozszerzenie wymaga osobnych niezmiennych rewizji Sigma, walidacji źródła
przed wykonaniem i wąskiej projekcji SQL do istniejącego wdrożenia.
Dowolna nazwa, severity lub tag reguły nie może udawać nowego niezależnego
zachowania ani potwierdzonego ataku.

## Podzbiór i semantyka

- Jedna definicja UTF-8, maksymalnie 65536 bajtów; wymagany niezerowy UUID `id`.
- `title`, `logsource` i `detection` opisują kontrolowane wykonanie.
  Opcjonalne `level` domyślnie ma wartość medium.
  Dozwolone dodatkowe pola dokumentacyjne są wyliczone w kompilatorze.
- `equals`, `contains`, `startswith`, `endswith`: tekst porównywany bez
  rozróżnienia wielkości liter. Liczby całkowite mają ścisły typ i zakres pola.
  Równość to pole bez modifiera; `|equals` nie jest obsługiwanym zapisem.
- Mapa selekcji łączy pola AND; lista wartości/alternatyw używa OR.
  `condition` obsługuje nazwy selekcji, AND, OR, NOT i nawiasy.
- Brak pola nie spełnia predykatu porównania. NOT odwraca logiczny wynik
  selekcji, również dla brakującego pola; autor musi uwzględnić to w regule.
- Pola i aliasy są ograniczone do rzeczywistego schematu normalizacji
  oraz jawnie obsługiwanych dostawców. Aliasy innego dostawcy są odrzucane.
- Brak wildcardów, regex, `all`, agregacji, Sigma correlation, full-text,
  `1 of`/`all of`, arbitralnych rozszerzeń, accessors i wykonania kodu.
  Nieobsługiwana składnia jest błędem, a nie cichym uproszczeniem.

YAML używa [SafeLoader](https://pyyaml.org/wiki/PyYAMLDocumentation)
z dodatkowymi kontrolami. Aliasy, kotwice, jawne tagi, dyrektywy i wiele
dokumentów są odrzucane przed konstrukcją obiektów. Merge keys i duplikaty
kluczy są odrzucane przy konstrukcji zwykłych map przez SafeLoader.
Liczba węzłów, głębokość, selekcje, predykaty, wartości i condition mają
osobne limity. Kompilacja wytwarza dane AST, bez `eval` i regex użytkownika.

## Publikacja i wykonanie

Import tworzy rewizję 1 i wyłączone wdrożenie. Powtórzenie źródła identycznego
z bieżącą rewizją jest idempotentnym odczytem istniejącej wersji. Inna definicja tego samego UUID
wymaga jawnego dodania rewizji. Nowa rewizja ponownie wyłącza regułę.
Aktualizacja wymaga bieżącego `If-Match`; konflikt nie nadpisuje zmian.
Limit to 100 reguł i 20 rewizji na regułę; test przyjmuje do 25 zdarzeń.

Reguły włączone są oceniane przy kolejnych oczekujących jobach detekcji.
Import i odczyt nie odtwarzają zakończonych jobów. Snapshot alertu wiąże UUID,
rewizję, źródło, AST, wersję wykonawcy i hashe. Weryfikacja korzysta z
utrwalonej rewizji i dowodu zdarzenia, a nie z deklaracji przesłanej w alercie.
Pierwotne snapshoty i wersje wykonawców reguł wbudowanych pozostają zachowane.

## Ryzyko, MITRE i bezpieczeństwo

Nowa polityka `risk-policy-v3` dodaje osobne podstawy severity. Zweryfikowana
reguła Sigma wpływa na składnik D. Nie ustanawia kontrolowanej rodziny
zachowania ani niezależnych dowodów C/E; confidence pozostaje unknown.
Arytmetyka istniejących sygnałów jest zachowana. Zapisane obliczenia v2
pozostają odczytywalne w historycznej postaci; GET ich nie przelicza.

Tagi `attack.tNNNN[.NNN]` muszą odpowiadać aktywnym technikom lokalnego
katalogu. Mapowanie nadal oznacza candidate association, bez potwierdzenia
ataku i bez dodatkowych punktów kontekstowych T. Pokrycie rozdziela reguły
skonfigurowane/włączone od obserwacji w wybranym zakresie live albo replay.

Role i uprawnienia są egzekwowane przez API. Walidacja/odczyt wymagają
`detections:read`, test `detections:test`, import i rewizje
`detections:import`, publikacja `detections:publish`. Mutacje odświeżają
uprawnienia i sesję po uzyskaniu blokady. Runtime nie otrzymuje szerokiego
INSERT ani UPDATE wersji wdrożeń; służy do tego kontrolowana funkcja SQL.
Nie zmienia to granicy zaufania istniejącego aplikacyjnego autora INSERT.

## Plan odbioru

1. Parser i czysty wykonawca: poprawne przykłady, negacje, typy, limity,
   nieobsługiwana składnia, niezmienność AST i różnice dostawców.
2. API i baza: role, konflikty, append-only, granty, downgrade, współbieżność,
   rollback, historia rewizji i brak skutków walidacji/testu.
3. Pipeline: nowe joby live/replay, retry, źródłowe dowody, ryzyko D-only,
   brak powielania C/E, historyczne v2 i mapowania MITRE.
4. Panel: import/rewizje, uprawnienia, loading/empty/error, konflikty,
   opóźnione odpowiedzi sesji, poprawne limity i bezpieczny tekst YAML.
5. Wspólna regresja, odizolowany start, upgrade głównej aplikacji,
   odczyt gotowości i restart procesów. Wyniki wpisujemy po ich wykonaniu.
