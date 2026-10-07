# ADR 0015 — statystyczne porównanie obserwowanej aktywności

Data: 2026-10-06. Status: przyjęta dla Etapu 9.

## Kontekst

Profile encji łączą niezmienne dowody według konserwatywnej, wersjonowanej
tożsamości. Potrzebujemy prostego UEBA z wyjaśnieniem, bez uczenia maszynowego
i bez wymyślania uprawnień kont na podstawie ich nazw.

## Decyzja

Dodajemy odczyt analizy profilu użytkownika lub hosta dla jednej zakończonej
doby UTC. Bazą porównania jest 28 poprzedzających ją pełnych dób, z uwzględnieniem
dni bez aktywności. Doba obserwacji nie trafia do własnego baseline. Każdy wynik
zawiera wersję polityki, zakres czasu, wartości porównania, punktację i dowody.

Obliczenie jest projekcją wykonywaną na żądanie. GET nie zapisuje baseline,
nie buduje indeksu i nie zmienia ocen ryzyka, alertów ani spraw. Późne zdarzenie
może zmienić wynik ponownego odczytu; nie nazywamy go niezmienną historyczną oceną.
Początkowy zakres nie obejmuje uczenia online ani automatycznego publikowania
anomalii przez proces w tle.

Wspólne minimum historii wynosi 20 zdarzeń na 7 aktywnych dniach. Poszczególne
wskaźniki mają dodatkowe minima właściwej grupy zdarzeń. Jawne stany braku
historii, niepełnego indeksu i nieobsługiwanej cechy zapobiegają przedstawieniu
braku danych jako oceny bezpieczeństwa. Odrzucamy niepewne czasy źródła.

Zachowujemy istniejącą tożsamość i role aktora/celu. Logowanie Windows dotyczy
konta docelowego. Nowy host jest wykrywalny wyłącznie dla tożsamości użytkownika,
która wiarygodnie obejmuje wiele hostów w jednym źródle. Nie łączymy nazw kont
między maszynami lub źródłami. Replay wymaga dokładnego dataset/run i ma własny
baseline. Nie rozpoznajemy członkostwa w grupie administratorów z nazwy konta.

Odczyt ma limity czasu SQL, liczby i rozmiaru dowodów. Przekroczenie limitu lub
niespójność dowodu zwraca błąd zamiast częściowej oceny. Uprawnienia wymagają
łącznie odczytu zdarzeń, alertów i incydentów, tak jak profile encji.

## Konsekwencje

Rozwiązanie jest deterministyczne dla tego samego zbioru zweryfikowanych danych
i wersji polityki. Progi są heurystyką do przeglądu przez analityka; punktacja
nie jest prawdopodobieństwem ataku. Okna UTC upraszczają odtwarzanie, ale nie
odwzorowują lokalnych zmian ani świąt. Rozszerzenie o kalendarze, trwałą historię
ocen i proces automatyczny wymaga osobnego kontraktu i walidacji.

## Alternatywy i ponowne rozważenie

Odrzucamy na tym etapie model ML: dostępne dane nie zapewniają wiarygodnego
treningu ani kalibracji. Odkładamy trwałe baseline i kolejkę ewaluacji do chwili,
gdy potrzebne będą ciągłe powiadomienia lub historia wersji ocen. Zwiększenie
limitów wymaga pomiaru obciążenia; lepsze rozpoznawanie administratorów wymaga
potwierdzonego pola uprawnień, a nie heurystyki nazwy użytkownika.

Dowodem akceptacji są testy granic czasu, izolacji, braków danych, źródłowych
dowodów oraz rzeczywistej integracji PostgreSQL, opisane w
[raporcie walidacji](../validation-ueba.md).
