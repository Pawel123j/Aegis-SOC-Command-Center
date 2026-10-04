# ADR 0011 — wersjonowane reguły Sigma i jawny zakres ich dowodu

Data: 2026-10-04. Status: decyzja przyjęta; Etap 5 wdrożony.
Rozszerza ADR 0004, 0009 i 0010.

## Kontekst

Detektor obsługuje kontrolowane reguły i niezmienne alerty. Import YAML wymaga
rozszerzalnego formatu, powtarzalnego wykonania oraz granic kosztu i dostępu.
Autor importowanej reguły może deklarować severity i tag MITRE, ale takie
metadane nie są skalibrowaną pewnością ani niezależną rodziną zachowania.

## Decyzja

Wprowadzamy jawny podzbiór Sigma i czysty wykonawca `sigma-subset-v1`.
Wymagany UUID wiąże append-only tożsamość z append-only rewizjami źródła
i skompilowanego AST. Hashe źródła i AST oraz wersja wykonawcy są częścią
historycznego dowodu. Kontrolowana funkcja SQL wybiera istniejącą rewizję
w projekcji wdrożenia; nie otwiera runtime ogólnych grantów dla wdrożeń.
Import i nowa rewizja pozostawiają regułę wyłączoną. Publikacja wymaga
uprawnienia i aktualnego numeru wersji. Zakończone joby nie są odtwarzane.

Polityka `risk-policy-v3` dodaje `severity_baselines`, oddzielone od sygnałów
czterech kontrolowanych rodzin. Zweryfikowana Sigma daje D z deklarowanej
severity. C/E nadal wynikają wyłącznie z istniejących kontrolowanych sygnałów;
reguła Sigma na tym samym zdarzeniu nie zwiększa ich liczby. Przy samej Sigma
C/E są unknown. Pozostałe nieznane konteksty nadal mają zero punktów.
Wagi i deduplikacja wbudowanych sygnałów pozostają zachowane. Zmiana kontraktu
i pochodzenia wejścia wymaga nowej wersji/hash polityki, nawet bez zmiany wag.
Stare obliczenia v2 zachowują JSON, hashe i wynik. Odczyt historii nie mutuje
danych; nowa ocena v3 powstaje po rzeczywistej mutacji lub jawnej rekalkulacji.

MITRE weryfikuje tagi w przypiętym katalogu. Snapshot mapowania wiąże
utrwaloną rewizję i dowód zdarzenia. Candidate association pozostaje
niepotwierdzonym powiązaniem; nie przyznaje dodatkowego kontekstu ryzyka T.
Aktualne konfiguracje i historyczne obserwacje mają osobne liczniki.

## Alternatywy

Pełna interpretacja Sigma w pierwszym przyroście rozszerzałaby zakres ponad
możliwości bieżącej normalizacji. Ciche ignorowanie wildcardów lub modifierów
zmieniłoby intencję reguły. Nadpisanie YAML utraciłoby możliwość odtworzenia
alertu. Uznanie każdej nazwy Sigma za niezależną rodzinę podnosiłoby ryzyko
przez liczbę duplikatów. Rozpoznawanie proof wyłącznie ze snapshotu alertu
pozwalałoby samemu źródłu przypisywać sobie zaufanie.

## Konsekwencje

Nie każda publiczna reguła jest obsługiwana; capabilities i błąd walidacji
wyjaśniają granice. Nowe rewizje wymagają ponownego włączenia. Zdarzenia
oczekujące mogą użyć bieżącej publikacji, lecz historyczny alert zachowuje
własną wersję. Same reguły Sigma mają ograniczone podstawy oceny ryzyka.
Append-only chroni istniejące wpisy, ale autor nowych INSERT pozostaje częścią
zaufanego runtime aplikacji, zgodnie z wcześniejszymi ADR.

## Dowód akceptacji i ponowne rozważenie

Wymagane są testy parsera i limitów, role/authority-after-lock, wersje i retry,
granty/rollback, rzeczywisty pipeline live/replay, niezmienna historia v2,
Sigma D-only, brak inflacji C/E oraz spójne pokrycie MITRE.
[Raport Etapu 5](../validation-sigma.md) zawiera wykonane wyniki i ograniczenia.
Rozszerzenie składni, dostawców lub źródeł confidence wymaga nowej wersji
wykonawcy/polityki i ponownej kontroli zgodności historycznych dowodów.
