# ADR 0008 — finalizacja korelacji i zachowanie dowodów

Status: przyjęta dla Etapu 2. Data: 2026-10-01.

## Kontekst

Etap 2 wymaga reguł liczących zdarzenia i rozpoznających ich kolejność.
Dotychczasowy detektor ocenia jeden immutable snapshot. Sam wspólny adres IP
nie identyfikuje użytkownika, a maksymalna data dostarczonego eventu może
pochodzić z błędnego zegara. Alert po restarcie musi zachować te same dowody.
Szerszy projekt PHASE 0 obejmował również scalanie spraw i graf relacji;
ten przyrost realizuje reguły wielozdarzeniowe oraz ich alerty.

## Decyzja

Osobny `app.correlator` czyta niezmienne snapshoty PostgreSQL. Trwałe zadania,
watermark i unikalny klucz dopasowania pozwalają ponawiać pracę. Zapis alertu,
wielu dowodów, automatycznej sprawy High/Critical, audytu i checkpointu ma
jedną transakcję. ClickHouse ani dostarczenie komunikatu nie są jej warunkiem.
Live stosuje deployment aktywny podczas finalnej oceny kotwicy, pod tą samą
blokadą co zmiana reguły. Włączenie nie przelicza już przetworzonych kotwic;
wcześniejsze poprawne zdarzenia mogą stanowić dowody nowej kotwicy.

Live obejmuje jedną lokalną organizację i wiele źródeł, zgodnie z ADR 0007.
Replay ma dokładny zakres dataset/run i wymaga jawnego zamknięcia manifestu.
Zamknięcie zapisuje liczbę, identyfikatory i hashe wejścia oraz snapshot
wersji i aktywności reguł; późniejsza zmiana deploymentu nie zmienia przebiegu.
Późniejsze przyjęcie
nie poszerza istniejącego przebiegu. Nie deklarujemy rekonstrukcji historycznej
pracy analityka ani równoważności dowolnego wycinka replay z live.

Live zachowuje 120 s bufora z ADR 0004. Nowy event kwalifikuje się, gdy jego
czas leży od 120 s przed czasem przyjęcia do 30 s po nim i nie przekracza
wcześniej zamkniętej granicy wstecz. Przyszłe daty oraz zbyt późne zdarzenia
otrzymują jawny wynik pominięcia korelacji; oryginalny log pozostaje dostępny.
Watermark wynika z czasu serwera minus bufor, nigdy z największej daty logu.
Nie może wyprzedzić zaległego przyjętego wejścia lub normalizacji.
Pierwszy przyrost stosuje konserwatywną barierę całego inboxu: również
niezamknięty backlog replay może wstrzymać postęp live. Gdy brakujący zapis
zostanie znormalizowany i odkryty, kolejne przebiegi mogą przesunąć granicę.

Bariera zamknięcia używa tej samej blokady pojemności ingestion, po której
przyjęcie nadaje `received_at`. Zapobiega to zamknięciu okna przed zatwierdzeniem
wcześniejszego przyjęcia. Kolejność blokad to ADMIN, następnie capacity.
Zdarzenia w zaakceptowanym zbiorze są sortowane po czasie i ID. Determinizm
dotyczy identycznego manifestu oraz wersji reguł i konfiguracji; dowolnie późne
logi nie są obietnicą ponownego otwarcia finalnych alertów.

Silna tożsamość hosta używa `host.id`; zastępcza nazwa hosta ma zakres źródła.
Tożsamość użytkownika obejmuje stabilne ID i host albo realm/nazwę/host.
Windows 4624/4625 używa konta logowania z `user.target`; zmiana grupy używa
wykonawcy z `user`, zachowując odrębne konto docelowe. Nieznany SID nie jest
wspólną tożsamością użytkowników. Windows może łączyć domenę/nazwę/host przy
brakującym SID; sprzeczne znane SID blokują dowód. Nie rozwiązujemy dowolnych
aliasów kont między platformami. Proces wymaga
`entity_id` wraz z hostem, a nie PID. Brak wymaganej encji nie jest zastępowany
IP. Reguła określa AND/OR predykatów, licznik etapu, kolejność, wspólne encje
i maksymalny span całej sekwencji. Znane konflikty sesji po udanym logowaniu
blokują łańcuch. Reguła wieloetapowa dodatkowo wymaga tego samego trwałego
procesu dla PowerShell i późniejszego połączenia wychodzącego.

Zapytania oraz liczba dowodów są ograniczone. Przekroczenie limitu daje jawne
`incomplete`, a nie pozornie pełne dopasowanie z obciętego zbioru. Jest to
utrwalony końcowy wynik tej kotwicy; Etap 2 nie dodaje automatycznej naprawy
przekroczonego limitu ani publicznego retry korelacji.
Dowód jest minimalnym deterministycznym zbiorem spełniającym liczności etapów,
a nie listą wszystkich logów z okna. Kolejne kwalifikujące się kotwice mogą
tworzyć odrębne alerty; ten przyrost nie dodaje suppression bucket.
Historyczny alert zachowuje wszystkie snapshoty i ich hashe, niezależnie od
późniejszej zmiany deploymentu. Dotychczasowy pojedynczy dowód pozostaje
zgodnym polem kotwicy. Incydent agreguje encje i czas ze wszystkich dowodów.
Automatyczne sprawy nie scalają ani nie otwierają ponownie spraw analityka.

## Alternatywy i konsekwencje

Natychmiastowe wyniki tymczasowe wymagałyby wycofywania alertów oraz historii
rewizji. Watermark z czasu eventu pozwoliłby jednemu błędnemu zegarowi zamknąć
inne okna. Wybrany bufor daje przewidywalną finalizację i jawnie ogranicza
spóźnienie; opóźnione importy wymagają replay. Silne encje mogą zmniejszać
liczbę dopasowań na ubogich logach, ale nie dopowiadają tożsamości sprawcy.

Osobny proces izoluje pracę okien od detektora pojedynczego zdarzenia.
Nie dodajemy zależności ani nowej bazy. Pola risk/confidence pozostają NULL
do właściwego silnika ocen. Pełny graf, merge, aliases, storyline i reconstruct
zachowują status przyszłego projektu.

## Dowód i ponowna ocena

Wymagane są testy czystego evaluatora oraz rzeczywistego PostgreSQL: granice
liczników i czasu, permutacje wejścia, NAT, brak encji, różne procesy, backlog,
late/future, replay, restart, równoległe ponowienie, granty i rollback audytu.
Wyniki wykonanych kontroli zawiera [raport Etapu 2](../validation-correlation.md).
Zmiana bufora, zakresu tożsamości, limitów albo finalnych dowodów wymaga nowej
wersji evaluatora i ponownej oceny tej decyzji.
