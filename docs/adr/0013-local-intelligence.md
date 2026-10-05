# ADR 0013 — lokalne IOC i zachowane dowody dopasowania

Status: przyjęta. Data: 2026-10-05. Kontynuacja
[ADR 0009](0009-explainable-risk.md), [0011](0011-versioned-sigma-rules.md)
i [0012](0012-observed-entity-profiles.md).

## Kontekst

IOC mogą zmieniać reputację, a dopasowanie współdzielonego IP lub URL samo
nie potwierdza ataku. Ponowny lookup podczas GET zmieniłby wyjaśnienie starego
alertu bez nowego dowodu. Zewnętrzne zapytania ujawniałyby obserwowane wskaźniki.
Niewłaściwa normalizacja może połączyć różne adresy lub nazwy.

## Decyzja

Katalog lokalny IP/domain/URL/hash używa niezmiennych rewizji, kanonicznego
JSON i SHA256. Ograniczona funkcja SECURITY DEFINER wybiera kolejną rewizję,
sprawdza aktora manager/admin i wymaga wspólnej blokady organizacji.
API ponownie sprawdza aktywną sesję/uprawnienia po oczekiwaniu. Runtime ma
SELECT/INSERT, bez bezpośredniego UPDATE/DELETE/TRUNCATE. Niepusta warstwa
odmawia downgrade, a pusta pozwala odwrócić migrację bez zmiany starszej historii.

Pierwsza analiza eventu zapisuje receipt, także zero matches, i dokładne
field matches z oryginalną rewizją. Detektor commit obejmuje ledger, alert,
ocenę, mapowanie i checkpoint. SQL pilnuje zakresu, parent/revision/hash oraz
liczności; Python sprawdza oryginalny raw/normalized source i typed extraction.
INSERT jest granicą zaufanego aplikacyjnego writera; to nie forensic WORM
przeciw administratorowi DB. Odczyt i recalc odrzucają uszkodzony zachowany dowód.

Normalizacja jest konserwatywna i wersjonowana. [RFC 3986 §6.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2)
uzasadnia lowercase host/scheme, percent hex oraz HTTP default port/empty path.
Path/query/fragment, puste delimitery i kodowane separatory pozostają zachowane,
żeby nie zakładać równoważności zasobów lub tras aplikacji.
[Oficjalne IDNA](https://github.com/kjd/idna) zapewnia IDNA2008/UTS46 nontransitional;
stdlib IDNA2003 mogłoby złączyć `faß.de` z `fass.de`. Istniejący przypięty
pakiet idna 3.20 staje się jawną zależnością bez nowych dystrybucji.

Malicious match tworzy lokalny medium TI alert bez rodziny zachowania i
bez technik MITRE. Opt-in risk-policy-v4 dodaje maksymalny, osobny kontekst I;
malicious daje co najmniej 5 punktów także przy nieznanym confidence,
z jawną deklaracją źródła. TI baseline daje D30 i C/E0. Bez TI używany jest
niezmieniony v3; historyczne v2/v3 nie są przepisywane. Maksymalnie 100
najsilniejszych matches zachowuje maksimum I i ujawnia truncation.

Interfejs providera oddziela przyszłe integracje, lecz dostępny jest wyłącznie
provider lokalny. Nie wykonuje się żadnego pobrania URL, DNS ani zewnętrznego lookup.

## Alternatywy

Live lookup z aktualnej rewizji przy każdym odczycie utraciłby historię.
Automatyczne przeliczanie po imporcie zmieniłoby stare oceny bez jawnego działania.
Jedna mutable tabela utrudniłaby audyt i odtworzenie. Wiele zewnętrznych providerów
przed lokalnym kontraktem rozszerzyłoby zakres bez zweryfikowanego źródła.

## Konsekwencje

Limit katalogu 1000, rewizji 50, importu 100, event matches 32 i risk context 100
utrzymuje bounded workload. To początkowe limity lokalnego deploymentu.
Starsze eventy wymagają jawnego backfill brakujących receipts; istniejące receipts
pozostają niezmienne. Replay analizowany dziś nie udaje historycznej reputacji.
Adresy URL pozostają tekstem w UI, a confidence i reputacja są source assertions.

## Dowód akceptacji i ponowne rozważenie

Dowód: [raport Etapu 7](../validation-intelligence.md), unit normalizacji
i ręcznej punktacji, real integration źródeł/ledger/migracji/rollback/RBAC oraz
frontend API/session/conflict tests. Pełny zalogowany przebieg przeglądarkowy
jest odrębnie raportowany. Wrócić do decyzji przy potrzebie external providerów,
TTL reputacji, proposals workflow, większego katalogu lub nowego normalized
schema z typowanym DNS domain. Każda zmiana semantyki wymaga nowej wersji.
