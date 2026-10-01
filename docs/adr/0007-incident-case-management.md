# ADR 0007 — incydenty i ich zakres operacyjny

Status: przyjęta dla etapu 1 rozbudowy SOC. Data: 2026-10-01.

## Kontekst

Nowa prośba użytkownika wymaga najpierw rzeczywistego Incident Management,
przed silnikiem korelacji i ryzyka. Istniejące źródła live mają osobne
`dataset_id`, a pipeline przechowuje niezmienne dowody i transakcyjny audyt.
Wcześniejszy dokument projektowy proponował inne statusy; najnowsze wymagania
wyznaczają `new`, `investigating`, `contained`, `resolved`, `closed`.

## Decyzja

Incydent jest osobnym agregatem PostgreSQL, z wersją do `If-Match`,
właścicielem, severity, tagami oraz dopinanymi alertami. Zmiana agregatu,
historia działań i audyt zatwierdzają się w jednej transakcji. Notatki i
historia nie są edytowalne przez runtime. Odpinanie alertu zachowuje historię
i dowód zamiast usuwać fakt wcześniejszego powiązania.

Sprawa live może zawierać alerty wielu źródeł w tej samej lokalnej organizacji,
wyłącznie w trybie live i z zerowym run UUID. Każdy dowód zachowuje własne
source/dataset/run. Sprawa replay jest ograniczona do jednego dataset i run.
Nie łączymy live z replay ani niezależnych przebiegów demonstracyjnych.
To doprecyzowuje wcześniejszą ogólną zasadę izolacji dataset; dataset źródła
live nie jest granicą organizacji ani kontroli dostępu.

Każdy nowy alert High/Critical tworzy własną automatyczną sprawę w tej samej
transakcji detektora. Unikalny klucz alertu chroni przed duplikacją po retry.
Nie grupujemy automatycznie sekwencji i nie przetwarzamy historycznych
alertów podczas upgrade. Medium/Low mogą trafić do sprawy przez analityka.

Risk i confidence pozostają NULL do wdrożenia sensownej oceny. Severity
operatora jest osobnym polem i nie stanowi ukrytego algorytmu ryzyka.
Chronologia obserwacji korzysta z event time, historia pracy z czasu serwera.

## Alternatywy i konsekwencje

Ścisłe ograniczenie każdego incydentu do dataset źródła uniemożliwiłoby
połączenie logów Windows i firewalla w jednej sprawie operacyjnej.
Jedna wspólna przestrzeń dla wszystkich trybów mieszałaby natomiast demo
z rzeczywistą aktywnością. Wybrany model zachowuje pochodzenie dowodów
i izolację replay, bez zmiany schematu ingestion.

Tworzenie sprawy dla każdego alertu zwiększałoby szum. Początkowa automatyka
dotyczy High/Critical; właściwe grupowanie i kontrola liczby spraw zostają
zadaniem etapu 2. Wprowadzenie wielu organizacji będzie wymagało jawnego
organization/tenant ID i kontroli dostępu, a nie reinterpretacji dataset.

## Dowód akceptacji i ponowna ocena

Wymagane testy: cross-source live, odrzucenie mieszanych mode/run,
deduplikacja automatycznego utworzenia, rollback audytu, concurrent edits,
RBAC i trwałość odpiętych dowodów. Wyniki należy odnotować w
[walidacji etapu 1](../validation-incidents.md).

Ponownie ocenić politykę automatycznych spraw po uruchomieniu korelacji,
pomiary szumu/obciążenia oraz granice danych przed obsługą wielu organizacji.
