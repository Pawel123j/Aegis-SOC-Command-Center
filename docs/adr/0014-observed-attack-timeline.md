# ADR 0014 — chronologia zachowanych obserwacji sprawy

Data: 2026-10-05. Status: przyjęta dla Etapu 8.

## Kontekst

Incydent zachowuje audyt pracy analityka i dowody wielu alertów. Ich kolejność
powstawania różni się od kolejności zdarzeń źródłowych. Jeden event może stanowić
dowód kilku alertów, a korelacja zachowuje także eventy poprzedzające anchor.
Istniejący indeks encji ma receipts alertów i referencje wszystkich dowodów.
Starsze alerty mogą wymagać jawnego backfill.

## Decyzja

Dodajemy osobną graficzną chronologię obserwowanych eventów aktywnie przypiętych
alertów. Kolejność `(timestamp UTC, UUID)` zachowuje mikrosekundy i przyszłe
czasy źródła. Deduplikacja event UUID zachowuje wszystkie odniesienia do alertów,
w tym oznaczenie FP. Otwieramy istniejący widok zdarzenia z oryginalnym snapshotem.

Odczyt wykorzystuje `AlertEventReference` i `EntityAlertReceipt`, bez nowych
tabel lub procesu. Jeden SELECT CTE ustala zakres, liczby, fingerprint i stronę.
Metadane wszystkich aktywnych alertów mają kontrolę zakresu i liczności;
wybrane eventy mają pełną weryfikację źródła raw/normalized oraz dokładną
zgodność kopii alertowych. Nie deklarujemy weryfikacji dokumentów innych stron.

Osobny podpisany kursor wiąże principal, sprawę, limit, fingerprint i ostatni
klucz. Fingerprint zawiera powiązania, wersje/statusy alertów oraz stan indeksu.
Zmiana wymaga odświeżenia, także gdy backfill nie zmienia wersji sprawy.
Live dopuszcza wiele źródeł z zerowym run; replay izoluje dokładny dataset/run.
Odczyt wymaga trzech istniejących permissions i aktualnej sesji.

Brak receiptu jest jawnie pending. GET nie buduje indeksu. Aktualny panel
pozostaje osobny od audytu analityka i zachowanej historii odpiętych dowodów.
Graficzna linia pokazuje porządek obserwacji; nie ustanawia przyczynowości
ani domniemanych etapów ataku.

## Alternatywy

Materializacja wszystkich pełnych kopii alertów może wciągnąć do aplikacji
100×100 dużych dokumentów przed paginacją. Nowy ledger powieliłby istniejące
referencje i wymagał migracji oraz kolejnego backfill. Łączenie historii audytu
z czasem eventów utrudnia rozróżnienie działań analityka i faktów źródłowych.
Mutable link nie odtwarza całej historii kolejnych odpięć i ponownych przypięć;
ten zakres pozostaje w istniejącym audycie.

## Konsekwencje

Strona ma najwyżej 25 eventów i 4 MiB wybranych dokumentów. Sprawa zachowuje
dotychczasowe granice 100 aktywnych alertów i 100 dowodów na alert. Niepełność
indeksu jest widoczna. Frontend chroni widok i kliknięcia przed późnymi
odpowiedziami poprzedniej sesji. Granica zaufania DB pozostaje taka jak dla
dotychczasowych niezmiennych dowodów; projekcja nie jest forensic WORM.

## Dowód akceptacji i ponowne rozważenie

[Raport Etapu 8](../validation-attack-timeline.md) zapisuje testy paginacji,
źródła, deduplikacji, uprawnień i sesji oraz pełną regresję i lokalny start.
Wrócić do decyzji przy większych sprawach, potrzebie historycznej migawki linków,
badaniu szerszego kontekstu źródłowego albo nowym modelu hipotez przyczynowych.
