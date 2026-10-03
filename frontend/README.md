# Panel Aegis SOC

React 19.3.0, TypeScript 6.0.3, Vite 8.3.1, Node.js 24.19.0 i pnpm 11.19.0.
Panel działa za lokalnym proxy pod tym samym origin co API.

Widoki: logowanie, przegląd, zdarzenia i dowody, alerty z decyzjami analityka,
incydenty z notatkami i osią czasu, trzy reguły pojedynczych zdarzeń i pięć reguł
korelacji, źródła z własnymi
kluczami, status przetwarzania i retry, ocena ryzyka alertów i incydentów
oraz MITRE ATT&CK Coverage.
Dane i zachowane obliczenia pochodzą z API.

Incydenty można tworzyć ręcznie lub z alertu, łączyć z kolejnymi alertami,
przypisywać analitykom i prowadzić przez kolejne statusy. Widok szczegółów
pokazuje encje i nazwane powiązania MITRE z rzeczywistych alertów, zachowane dowody,
notatki oraz stronicowaną historię. Odpięcie alertu zachowuje jego oryginalny
dowód. Lista alertów i incydentów oraz przegląd pokazują wynik ryzyka 0–100.
Wynik zero różni się od braku obliczenia. Pewność pozostaje jawnie nieznana,
gdy nie dostarczono danych do jej oceny. Zamknięcie ani opanowanie sprawy nie
uruchamia akcji na urządzeniach.

Szczegóły alertu i incydentu pokazują każdy składnik ryzyka, punkty,
uzasadnienie, limit, sumę przed ograniczeniem i końcowy wynik. Wynik jest
priorytetem analizy, nie prawdopodobieństwem ataku. Brak reputacji IOC,
znaczenia hosta lub użytkownika, taktyk MITRE albo potwierdzonej historii
zachowania jest wyraźnie oznaczony i nie oznacza, że źródło jest bezpieczne.
Historia pobiera na żądanie najnowsze 10 obliczeń i sygnalizuje, gdy istnieją
starsze wyniki. „Wersja oceny” oznacza kolejne obliczenie ryzyka dla danego
alertu lub incydentu, niezależnie od wersji zmian analityka. Politykę i jej
progi można pobrać przez „Zasady punktacji”, zgodnie z uprawnieniami.
Powiązane alerty mają osobny przycisk „Ocena ryzyka”, także gdy obejmują
tylko jedno zdarzenie. Jeśli historia zawiera nowszy wynik, panel oznacza go
osobno i udostępnia odświeżenie szczegółów. Do tego czasu wynik i uzasadnienie
w szczegółach dotyczą tej samej zachowanej oceny. Odświeżenie historii nie
zmienia ustaleń analityka.

Analityk może przejąć sprawę i zwolnić własne przypisanie; kierownik SOC
lub administrator może przypisać inną osobę i otworzyć zakończoną sprawę
ponownie. Backend sprawdza wszystkie uprawnienia. Każda zmiana istniejącego
incydentu używa jego wersji w `If-Match`. Konflikt zachowuje szkic i wymaga
świadomego odświeżenia przed kolejną zmianą. Tworzenie ponowione po błędzie
sieci zachowuje identyczny formularz i `Idempotency-Key`, dopóki dane formularza
nie zostaną zmienione lub formularz nie zostanie zamknięty.

Pusta sprawa utworzona w panelu dotyczy live. Sprawa replay powstaje z wybranego
alertu replay i może łączyć tylko alerty tej samej sesji oraz zestawu danych.
Sprawy live mogą łączyć alerty z wielu źródeł. Oś czasu rozróżnia czas logu
od czasu działania analityka i pozwala otworzyć zachowany oryginał bez
uzależnienia od dostępności wyszukiwarki zdarzeń.

„Reguły detekcji” mają zakładki pojedynczych zdarzeń i korelacji. Korelacje
pokazują kolejność etapów lub próg liczby zdarzeń, okno czasu, wspólne encje
oraz warunki AND/OR. Widok szczegółów pobiera wersjonowaną regułę z API.
Kierownik SOC i administrator mogą ją włączać i wyłączać z `If-Match`;
analityk może przeprowadzić izolowany test, a osoba z rolą odczytu przeglądać
warunki. Konflikt zmiany wymaga jawnego odświeżenia katalogu.

Pokrycie przetwarzania pokazuje liczniki kolejki, rekordy spóźnione,
nieprawidłowy czas, kwarantannę i niekompletne dopasowania z rzeczywistego
API. Można sprawdzić domknięty zakres live oraz stan i SHA-256 zestawu replay.
Niepełna lista zakresów jest jawnie oznaczona.

„MITRE ATT&CK” wymaga łącznie uprawnień do odczytu detekcji, alertów
i incydentów. Widok pokazuje nazwy i identyfikatory taktyk, technik
i podtechnik katalogu Enterprise ATT&CK 19.2, liczbę różnych alertów
i incydentów oraz osobno możliwości bieżących i włączonych reguł.
Powiązania z katalogiem wskazują możliwe zachowania; nie potwierdzają
udanego ataku ani zamiaru. Nie zmieniają składnika T oceny ryzyka,
który nadal wymaga potwierdzonego kontekstu.

Domyślny zakres obejmuje ostatnie 30 dni live, maksymalny 366 dni.
Filtry używają czasu zdarzenia alertu: od początku włącznie do końca
wyłącznie. Replay wymaga dokładnego Dataset ID i niezerowego Run ID,
aby nie sumować różnych sesji. Fałszywe alarmy są domyślnie pomijane
i można je jawnie uwzględnić. Rozwiązane alerty oraz zamknięte incydenty
pozostają uwzględnione; odpięte powiązania nie zwiększają liczników.
Każdy rekord liczy się raz w danym wierszu, lecz może wystąpić przy
kilku technikach. Łączne liczniki pochodzą z API i nie są sumą wierszy.

Panel jawnie pokazuje alerty bez mapowania, starsze alerty bez zachowanego
mapowania i powiązania z innym katalogiem. Pusty wynik nie potwierdza
bezpieczeństwa. Domyślnie lista technik obejmuje konfigurację reguł
lub obserwacje; pełny katalog jest dostępny po zaznaczeniu dodatkowej
opcji, z wyszukiwaniem, filtrem taktyki i stronami po 25, 50 lub 100 wierszy.
Katalog ma widoczną wersję, źródło, uznanie autorstwa MITRE, warunki użycia
i sumy kontrolne.

Reguły pokazują bieżące mapowanie, a szczegóły alertu zachowane mapowanie
z chwili detekcji. Oryginalny snapshot reguły pozostaje osobnym dowodem.
Incydenty agregują zachowane nazwy z aktywnie dołączonych alertów,
z pominięciem fałszywych alarmów, i pokazują wersje katalogów.
Źródło logu nie może nadać etykiety ATT&CK przez dodatkowe pola.
Zmiana zakresu, konta lub sesji usuwa wynik pokrycia; spóźnione odpowiedzi
nie nadpisują nowego zakresu. Metadane wyświetlane są jako tekst,
a odnośniki źródłowe są ograniczone do oficjalnych stron MITRE.

Test korelacji przyjmuje od 1 do 100 pełnych znormalizowanych rekordów JSON,
maksymalnie 64 KiB. Wyświetla liczbę dopasowań, wersję silnika, uzasadnienie
i każdy rekord dowodowy z przesłanego zestawu. Nie zapisuje alertu ani
incydentu i nie zmienia reguły. Test sprawdza kompletny przesłany zestaw od
razu; przetwarzanie live uwzględnia bufor opóźnionych logów i zaległą kolejkę.
Niekompletny wynik jest oznaczony osobno i nie jest traktowany jako brak
dopasowań. Szkic testu pozostaje po przełączeniu zakładki i odświeżeniu sesji
tego samego użytkownika.

Alerty korelacyjne, powiązane alerty incydentu, zachowane dowody i oś czasu
udostępniają wszystkie oryginalne zdarzenia dopasowania. Dla wielu rekordów
można wybrać konkretny dowód, sprawdzić jego SHA-256 oraz pierwszy i ostatni
czas. Starsze alerty nadal otwierają swój pojedynczy rekord. Odpięcie alertu
z incydentu zachowuje całą sekwencję dowodową. Dane logów i notatki są
wyświetlane jako tekst. Każde kliknięcie encji w oryginalnym zdarzeniu prowadzi
do rzeczywistego wyszukiwania w Event Explorer.

```text
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm lint
pnpm format
pnpm test
```

Build tworzy `dist`, montowany tylko do odczytu w nginx. Launcher Windows buduje
go automatycznie przed uruchomieniem usług. `pnpm dev` używa API na porcie 18080;
logowanie w dev wymaga ustawienia AEGIS_PUBLIC_ORIGIN na origin dev (bez CORS
lub wyłączania kontroli CSRF). Do próby całości użyj statycznego build i proxy.

JWT i klucze ingestion są tylko w pamięci. Web Locks serializują refresh między
kartami; BroadcastChannel przekazuje bieżącą sesję. Przeglądarka bez Web Locks
wymaga ponownego logowania po wygaśnięciu access tokena. Logout potwierdza
unieważnienie sesji na serwerze; awaria pozwala ponowić tę operację.

[Instrukcja uruchomienia](../docs/local-start.md), [zakres panelu](../docs/initial-soc.md).

Konfiguracja pnpm 11 jest w `pnpm-workspace.yaml`, w tym `storeDir` dla
lokalnego cache; `.npmrc` służy w tej wersji tylko registry/auth.
Źródło: [migracja pnpm 11](https://pnpm.io/blog/releases/11.0).
