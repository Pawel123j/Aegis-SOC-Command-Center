# Incydenty — etap 1 rozbudowy SOC

Incydent jest trwałą sprawą analityka, która może zawierać wiele alertów.
Panel „Incydenty” korzysta z backendu PostgreSQL; nie ma danych demonstracyjnych
zaszytych w widoku. Uzasadnienie architektury:
[ADR 0007](adr/0007-incident-case-management.md).
Wyniki wykonanych kontroli: [walidacja etapu 1](validation-incidents.md).

## Model i pochodzenie

Sprawa zawiera UUID, title, description, severity, status, owner, tags,
created/updated timestamps, first/last seen, version, risk_score i confidence.
Severity: `low`, `medium`, `high`, `critical`. Statusy:
`new`, `investigating`, `contained`, `resolved`, `closed`.

`risk_score` i `confidence` są początkowo NULL i nie przyjmują ręcznie
wymyślonej liczby. Silnik ryzyka powstanie w etapie 3. Severity sprawy może
zmienić analityk; przy tworzeniu z alertów domyślnie jest najwyższą severity
powiązanych alertów, z minimum Low.

Z aktywnych powiązań wynikają first/last seen, related users, hosts, IPs,
MITRE techniques i dataset_ids. Są to fakty z zachowanych snapshotów alertów,
nie domysły o tożsamości lub związku przyczynowym. Pusta sprawa ma brak
first/last seen; odpięcie ostatniego alertu przywraca brak tych danych.

Sprawy live mogą łączyć alerty z różnych źródeł w jednej lokalnej organizacji.
Ich `dataset_id` jest NULL, `run_id` jest zerowym UUID, a pochodzenie każdego
alertu zachowuje własny dataset/source. Replay wymaga jednego dataset i run;
nie można mieszać live/replay ani niezależnych uruchomień replay.

## Tworzenie, alerty i dowody

Analityk może utworzyć pustą sprawę albo wybrać do 100 alertów przy tworzeniu.
Ręczne utworzenie wymaga `Idempotency-Key`; retry z tym samym kluczem,
aktorem i żądaniem zwraca istniejącą sprawę. Inne body z tym samym kluczem
daje 409. Każda zmiana istniejącej sprawy wymaga aktualnego `If-Match`.

Każdy **nowy High/Critical alert** automatycznie tworzy własną sprawę w
transakcji alertu, audytu i checkpointu detektora. Unikalny `automatic_alert_id`
chroni przed duplikacją po retry. Nie ma automatycznego backfill historycznych
alertów ani grupowania kilku alertów w sekwencję; to zadanie etapu 2.
Sprawa automatyczna wymaga oceny analityka.

Do istniejącej sprawy można dopiąć albo odpiąć alert. Odpinanie dezaktywuje
powiązanie, zachowując jego historię i dostęp do niezmiennego dowodu.
Ponowne dopięcie tworzy kolejny wpis historii bez podmiany oryginalnego logu.
Snapshot normalized event, raw log, reguła, reason i SHA-256 pochodzą z
niezmiennego alertu PostgreSQL i nie zależą od dostępności ClickHouse.
Nie implementowano uploadu dowolnych plików ani retencji dowodów.

## Analitycy, historia i współbieżność

Read Only/Viewer czyta sprawy, notatki i dowody. SOC Analyst może tworzyć
i obsługiwać sprawy oraz przypisać siebie. SOC Manager/Admin może przypisać
innego aktywnego analityka; nie można przypisać Viewer ani wyłączonego konta.
Każde uprawnienie egzekwuje backend.

Notatki są zwykłym tekstem z czasem serwera i snapshotem autora. Nie mają
API usuwania ani nadpisywania. Timeline zachowuje utworzenie, dopięcie,
odpięcie, status, owner, pola i dodanie notatki. Dowody pokazują oddzielnie
czas obserwacji i czas dołączenia do sprawy. Z tego widoku można otworzyć
oryginalny event. Graficzny attack chain z korelacją zostaje etapem 8.

Mutacja, wpis timeline i audyt zatwierdzają się razem. Brak `If-Match` daje
428, stara wersja 412. Nieaktualna edycja nie nadpisuje pracy drugiego
analityka; należy odświeżyć sprawę. Po oczekiwaniu na blokadę backend
ponownie sprawdza rolę, enabled i ważność sesji.

Przejścia statusów: New → Investigating/Resolved;
Investigating → Contained/Resolved; Contained → Investigating/Resolved;
Resolved → Closed/Investigating; Closed → Investigating. Contained,
Resolved, Closed i reopen wymagają uzasadnienia. Reopen z Resolved/Closed
wymaga Manager/Admin. Zamknięta sprawa wymaga reopen przed zmianą pól
albo powiązań; można nadal dopisać append-only notatkę uzupełniającą.
Status Contained zapisuje deklarację analityka — sam nie blokuje hosta
ani konta i nie dowodzi wykonania reakcji infrastrukturalnej.

## API

Wszystkie ścieżki mają prefiks `/api/v1`.

| Endpoint | Kontrakt |
| --- | --- |
| `GET /incidents` | Lista, status/severity/owner/tag/mode/dataset/run, podpisany cursor |
| `POST /incidents` | Title, description, optional severity/tags/scope/alert_ids; `Idempotency-Key` |
| `GET /incidents/assignees` | Aktywni operatorzy możliwi do przypisania dla bieżącej roli |
| `GET /incidents/{id}` | Szczegół, aktywne alerty, encje, MITRE, najnowsze 50 notes/timeline; ETag |
| `PATCH /incidents/{id}` | Title/description/severity/status/status_reason/owner_id/tags; `If-Match` |
| `POST /incidents/{id}/alerts` | Dopina `alert_id`; `If-Match` |
| `DELETE /incidents/{id}/alerts/{alert_id}` | Odpina, zachowując dowód i historię; `If-Match` |
| `POST /incidents/{id}/notes` | Body 1–5000 znaków; `If-Match` |
| `GET /incidents/{id}/notes` | Paginowane notatki |
| `GET /incidents/{id}/timeline` | Paginowana historia działań |
| `GET /incidents/{id}/evidence` | Paginowane dowody aktywnych i odpiętych alertów |

Lista i kolekcje mają limit maksymalnie 100 rekordów na stronę. Podpisany
cursor jest przypisany do użytkownika, filtrów i kolekcji; ważność 15 minut.
Title: 1–256 znaków; description do 10000; do 20 unikalnych tagów po 64 znaki;
maksymalnie 100 aktywnych alertów. Tekst jest walidowany, renderowany jako
tekst i nie wykonuje skryptów.

## Kolejne etapy

Korelacja połączy sekwencje z jawnym dowodem i granicami czasu. Risk Engine
doda odtwarzalną ocenę z wyjaśnieniem. Katalog MITRE, entity pages, IOC,
graficzny attack timeline, UEBA, SOAR i raporty nie są jeszcze częścią
tego modułu; nie pokazujemy dla nich działających atrap.

## Graficzna chronologia zdarzeń — Etap 8

Panel Chronologia zdarzeń pokazuje unikalne oryginalne eventy aktywnie
powiązanych alertów od najstarszego czasu logu. Jeden event może mieć kilka
odnośników do alertów; FP pozostaje widoczne. Otwórz oryginalne zdarzenie
przechodzi do istniejącego widoku logu. Historia pracy analityka zachowuje
czas mutacji sprawy, a zachowane dowody obejmują również odpięte powiązania.
[Zakres, indeks, strony i sesja](attack-timeline.md).
