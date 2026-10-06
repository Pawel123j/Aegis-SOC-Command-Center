# Etap 8 — chronologia zdarzeń incydentu

Panel „Chronologia zdarzeń” pokazuje zachowane dowody aktywnie powiązanych
alertów od najstarszej obserwacji do najnowszej. Każdy event pojawia się raz,
ze wszystkimi odnośnikami do alertów, które go wykorzystują. Status fałszywego
alarmu jest widoczny przy odpowiednim odnośniku. Otwieranie zdarzenia korzysta
z istniejącego widoku oryginalnego logu.

Zakres pierwszej wersji stanowią dowody alertów przypiętych do sprawy.
Historia pracy analityka oraz odpięte dowody pozostają w osobnych istniejących
panelach. Graficzna linia wyraża kolejność obserwacji; potwierdzenie przebiegu
ataku i znaczenia poszczególnych kroków należy do analizy sprawy.

## Odczyt i zakres

`GET /api/v1/incidents/{incident_id}/attack-timeline?limit=25&cursor=...`
wymaga razem `incidents:read`, `alerts:read` i `events:read`. Odpowiedź ma
`Cache-Control: no-store`. Limit strony wynosi 1–25, domyślnie 25. Sprawa
ma najwyżej 100 aktywnych alertów, a alert najwyżej 100 dowodów.
Odczyt ma limit 60 żądań na minutę dla użytkownika i 3 s czasu zapytania SQL.

DTO zawiera `incident_id`, `incident_version`, `mode`, `dataset_id`, `run_id`,
`projection_version`, `view_fingerprint`, `total`, `index_status`, `items`
i `next_cursor`. `projection_version` wynosi `attack-timeline-v1`.
Każdy element zachowuje `event_id`, `event_sha256`, `event_snapshot` i `alerts`.
Odnośniki do alertów zawierają ID, tytuł, severity, status, typ detekcji,
regułę/wersję oraz czas przypięcia.

Live obejmuje wiele źródeł operacyjnej sprawy: sprawa ma `dataset_id = null`,
event zachowuje własny dataset źródła, a `run_id` jest zerowym UUID. Replay
wymaga dokładnego, niezerowego dataset i run sprawy. Odpowiedź ujawnia zakres.

## Czas, strony i zmiany

Porządek API to rosnące `(event.timestamp UTC, event_id)` z zachowaniem
mikrosekund. Przyszły timestamp logu jest dopuszczalny. Panel zachowuje kolejność
API i prezentuje lokalny czas; dokładny UTC i SHA-256 są dostępne w szczegółach.
Gdy parser użył czasu przyjęcia zamiast czasu źródła, flaga jakości jest widoczna.

Jedno zapytanie PostgreSQL ustala metadane sprawy, zestaw powiązań, stan indeksu,
fingerprint, liczbę eventów i stronę. Kursor jest podpisany, ważny krótko
i związany z użytkownikiem, sprawą, limitem, fingerprintem i ostatnim kluczem.
Kursor wygasa po 15 minutach od pierwszej strony; kolejne strony zachowują
pierwotny termin. Fingerprint obejmuje także wersje/statusy alertów oraz receipts i referencje.
Zmiana FP, powiązań lub uzupełnienie indeksu między stronami wymaga odświeżenia.
Spóźniony event po odświeżeniu trafia w odpowiednie miejsce według czasu logu.

## Zachowany dowód i niepełny indeks

Projekcja korzysta z istniejących `EntityAlertReceipt` i `AlertEventReference`.
Brak receiptu starszego alertu jest jawnie oczekującym indeksem.
`index_status` podaje `eligible_alerts`, `indexed_alerts`, `pending_alerts`
i `complete`. `total` liczy znane, zindeksowane eventy. GET pozostaje odczytem;
administrator może uzupełnić starszy indeks istniejącą ograniczoną operacją
backfill profili encji.

Metadane zakresu i liczności indeksu sprawdzane są dla wszystkich aktywnych
alertów. Pełna weryfikacja raw/normalized, SHA-256 i zgodności każdej kopii
w powiązanym alercie dotyczy pobranej strony. Uszkodzenie dowodu zwraca błąd
integralności. Istniejący receipt z niespójnymi referencjami również daje błąd.
Przed pobraniem pełnych dokumentów przez aplikację zapytanie sprawdza budżet
4 MiB dla wybranych wierszy raw/normalized i metadanych odnośników. Porównanie
kopii pozostaje w SQL i rozwija tablicę dowodów raz na powiązany alert.
Zbyt duża strona wymaga zmniejszenia liczby eventów.

## Błędy i sesja

409 `attack_timeline_changed` wymaga odświeżenia widoku.
409 `attack_timeline_integrity_mismatch` oznacza niespójny zachowany dowód.
409 `attack_timeline_limit_exceeded` oznacza przekroczenie granicy projekcji.
409 `attack_timeline_page_too_large` wymaga mniejszej strony.
Wspólne błędy uwierzytelnienia, uprawnień i walidacji zachowują dotychczasowy
kontrakt aplikacji.

Panel czyści dowody po zmianie sprawy, wersji lub sesji. Weryfikuje aktualnego
użytkownika i uprawnienia, anuluje stare żądania oraz odrzuca późne odpowiedzi
i kliknięcia poprzedniej sesji. Tytuły, nazwy i oryginalny log są tekstem.

Nie powstaje nowa tabela, migracja, usługa ani historia ocen. Head bazy pozostaje
`0011_intelligence`. Granica zaufanego writera/administratora DB pozostaje zgodna
z istniejącymi dowodami aplikacji. Wyniki i granice odbioru opisuje
[raport Etapu 8](validation-attack-timeline.md), decyzję
[ADR 0014](adr/0014-observed-attack-timeline.md).
