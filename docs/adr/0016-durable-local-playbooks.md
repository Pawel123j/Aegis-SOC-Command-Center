# ADR 0016 — trwałe, lokalne procedury reagowania

Status: przyjęta i zaimplementowana w Etapie 10. Data: 2026-10-08.

Mini SOAR uruchamia ręcznie opublikowaną, niezmienną wersję procedury z alertu.
Wejściem jest zweryfikowany dowód alertu; operator wybiera zdarzenie i stronę IP.
Rejestr akcji jest zamknięty. Nie przyjmujemy kodu, adresów webhook ani wyrażeń.
Każde wykonanie ma `execution_mode=simulation`, niezależnie od live/replay danych.
Blokada IP, izolacja hosta i webhook zapisują wyłącznie plan działania.

PostgreSQL jest kolejką i autorytatywnym rejestrem. Osobny proces `soar` pobiera
gotowy krok, zapisuje 30-sekundową dzierżawę i numer próby, po czym wykonuje go
w drugiej transakcji. Blokada uprawnień organizacji poprzedza blokady wierszy.
Przed efektem i jego zatwierdzeniem sprawdzamy dzierżawę, numer próby, anulowanie,
deadline, aktywność inicjatora, uprawnienia i wyłączenie procedury. Efekt lokalny,
wynik próby, audit i gotowość następnego kroku zatwierdzamy razem.

To świadome uproszczenie projektu PHASE 0: lokalne, krótkie akcje nie wymagają
drugiej kolejki Redis/Celery ani dodatkowego outbox. Zapis gotowości w tej samej
transakcji pełni rolę trwałego zawiadomienia. Restart procesu odzyskuje wygasłe
dzierżawy; nie ma obietnicy pojedynczego dostarczenia. Unikalny ledger efektów
oraz atomowość PostgreSQL zapobiegają ponownemu zatwierdzeniu skutku kroku.
Łącznie najwyżej trzy próby; po błędzie chwilowym przerwy 5 i 20 sekund.
Deadline wykonania wynosi 10 minut. Brak dowodu, naruszenie uprawnień i błędna
definicja są błędami trwałymi. Nie wykonujemy automatycznych triggerów detekcji.

Powiadomienie jest wpisem lokalnej skrzynki. Utworzenie incydentu używa istniejącej
usługi i otwartego powiązania alertu; zamknięta sprawa wymaga jawnej decyzji
operatora. Ocena ryzyka pokazuje przypięte obliczenie, jego politykę i wyjaśnienie;
SOAR nie dodaje uznaniowych punktów. Sprawdzenie TI używa przypiętego dowodu
pierwszej analizy zdarzenia. Brak analizy pozostaje widoczny jako pending.
Opcjonalne dodanie IOC wymaga uprawnień zarządzania TI: w live tworzy wyłącznie
nieaktywny wpis o nieznanej reputacji do przeglądu, istniejącego nie nadpisuje.
W replay także ten krok jest symulacją, aby nie zmieniać globalnego katalogu.

Zmiana definicji nie zmienia rozpoczętych wykonań. Wyłączenie zatrzymuje następne
kroki. Anulowanie zachowuje wcześniejsze skutki. Ręczne ponowienie tworzy nowy
run z `replay_of`, ponownie pokazuje plan i jawnie może utworzyć nowe lokalne
powiadomienie. Historia starego wykonania pozostaje niezmienna.

Bramki: rzeczywisty PostgreSQL, współbieżność, przerwanie przed i po commicie,
stara dzierżawa, retry, odebranie uprawnień, replay, brak ruchu do celów oraz UI.
Kontrakt i wynik odbioru: [SOAR](../soar.md).

Konsekwencją jest celowo mały, sekwencyjny silnik zależny od dostępności
PostgreSQL. Alternatywny transport Celery/outbox zwiększa liczbę granic
awarii bez korzyści dla obecnych krótkich transakcji. Decyzję należy
rozważyć ponownie przed dodaniem długich lub zewnętrznych akcji, równoległych
gałęzi albo większej skali. Takie rozszerzenie wymaga osobnego modelu
idempotencji, zezwoleń sieciowych i odbioru; sam nowy wpis konfiguracji
nie może włączać rzeczywistych skutków infrastrukturalnych.
