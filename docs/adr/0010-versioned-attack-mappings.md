# ADR 0010 — wersjonowane mapowania MITRE ATT&CK

Data: 2026-10-03. Status: decyzja przyjęta; Etap 4 zaimplementowany i zweryfikowany.

## Kontekst

Reguły przechowują już ID technik, lecz nie walidują ich względem lokalnego
katalogu. Nazwy i taktyki wymagają wersjonowanego źródła. Snapshot reguły
jest oryginalnym dowodem alertu i wejściem do deterministycznej oceny ryzyka;
zmiana jego treści naruszyłaby odtwarzalność wcześniejszych wyników.

## Decyzja

Używamy lokalnego, przypiętego Enterprise ATT&CK v19.2 w STIX 2.1.
Do repozytorium trafiają metadane tactics/techniques, pochodzenie i atrybucja.
Pełny źródłowy bundle pozostaje poza obrazem runtime. Loader sprawdza hash,
identyfikatory, URL, relacje i statusy. Nie pobiera danych w runtime.

Wersjonowana polityka mapowania korzysta z kontrolowanych definicji reguł.
Nowy alert otrzymuje odrębny niezmienny snapshot i indeksowane skojarzenia
techniki z taktyką, zapisane atomowo z alertem i audytem. Snapshot oryginalnej
reguły ani wcześniejsze obliczenia ryzyka nie są nadpisywane. Starszy alert
bez tego snapshotu pozostaje jawnie historyczny/niezmapowany; GET nie uzupełnia go.

Powiązanie technika→taktyka ma znaczenie `candidate_association`.
Używamy relacji oficjalnego katalogu, bez domyślania się zamiaru napastnika.
Sam login ani sesja root nie potwierdzają ataku. Składnik T oceny ryzyka
pozostaje unknown, dopóki odrębny adapter dowodowy nie ustanowi silniejszej przesłanki.

Coverage pokazuje distinct alert i aktywnie powiązane incident IDs,
z jawnym zakresem czasu/statusu oraz izolacją live/replay. Oddziela obecne
enabled reguł od historycznych dopasowań i nie sumuje wierszy jako całości.
Jedna odpowiedź agreguje tylko jedną wersję katalogu. Wymaga uprawnień
do wszystkich trzech domen: detections, alerts i incidents.

## Alternatywy

Zewnętrzne pobieranie katalogu przy każdym odczycie uzależniłoby panel od sieci
i zmieniających się metadanych. Dopisanie nazw do starego snapshotu reguły
naruszyłoby niezmienność dowodów. Liczenie wszystkich official tactic labels
jako potwierdzonych etapów ataku podniosłoby pewność bez wystarczającego dowodu.
Sumowanie wierszy liczyłoby te same alerty i incydenty wielokrotnie.

## Konsekwencje

Runtime jest samowystarczalny. Aktualizacja katalogu wymaga nowego artefaktu,
testów i jawnego przyrostu wersji; historyczne snapshoty zachowują swoje nazwy.
Brak mapowania obniża widoczne pokrycie i pozostaje wyjaśniony.
Append-only chroni wcześniejsze wpisy; writer aplikacji jest nadal zaufanym
źródłem nowego INSERT, analogicznie do alertów i audytu.

## Dowód akceptacji i ponowne rozważenie

Bramka obejmuje nieznane/wycofane ID, parent/subtechnique i relacje tactics,
hash, offline runtime, prawdziwe ingestion, izolację replay, wielokrotne
powiązania, false-positive/detach, distinct counts, granty, rollback i zgodność
API z panelem. Wyniki i granice dowodu opisuje [raport Etapu 4](../validation-mitre.md).
Decyzję należy rozszerzyć przy imporcie Sigma i wprowadzeniu nowych katalogów
lub adaptera potwierdzonych dowodów taktyk, z zachowaniem historycznych wersji.
