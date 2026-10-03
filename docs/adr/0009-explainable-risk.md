# ADR 0009 — wersjonowana i wyjaśniona ocena ryzyka

Data: 2026-10-03. Status: decyzja przyjęta, Etap 3 wdrożony.
Zastępuje projekt punktacji PHASE 0 w `risk-engine.md` dla bieżącego przyrostu.

## Kontekst

Alerty i incydenty mają nullable `risk_score`, a reguły nie deklarują
skalibrowanej pewności. Istnieją niezmienne dowody pojedynczych i skorelowanych
zdarzeń, decyzje analityka, audyt oraz izolacja live/replay. Reputacja IOC,
asset inventory, zweryfikowany katalog ATT&CK i potwierdzona historia
to dalsze etapy. Wypełnienie tych braków domysłami dałoby pozorną dokładność.
Nowa prośba wymaga zakresu 0–100 i wyjaśnienia każdego wyniku.

## Decyzja

Osobny czysty kalkulator używa całkowitoliczbowej polityki `risk-policy-v2`.
Poziomy odpowiadają nowej prośbie: 0–29 low, 30–59 medium,
60–79 high, 80–100 critical. To priorytet analityczny według jawnych wag,
nie prawdopodobieństwo ataku ani automatyczna decyzja o containment.

Podstawa D to największa waga jednej kwalifikującej się detekcji:
informational 5, low 15, medium 30, high 45, critical 55.
Znane confidence skaluje własną wagę przez `floor(weight*confidence/100)`.
Brak confidence zachowuje samą wagę severity i osobne oznaczenie unknown;
nie zapisujemy wymyślonego 100% ani nie nazywamy tej wartości pewnością.
Severity jednej reguły nie łączy się z confidence innej.

Liczba niezależnych jednostek dowodowych daje C: `min(9,3*max(0,n-1))`.
Przecinające się dowody tej samej kontrolowanej rodziny zachowań tworzą
jedną jednostkę, także przez przechodni overlap. Nazwa nowej reguły albo
opakowanie istniejącego sygnału nie są nową jednostką.
Liczba unikalnych contributed event IDs daje E: `min(12,2*max(0,m-1))`.
Wielokrotny alert nad tym samym zdarzeniem nie zwiększa m.
Incydent liczymy z aktywnych dowodów, nigdy jako sumę score alertów.
False positives nie uczestniczą w ocenie; resolved zachowuje dowód.
Ręczny priorytet/severity sprawy nie zmienia severity źródłowej detekcji.

Kontekst hosta, użytkownika, IOC, tactics, wcześniejszej potwierdzonej
aktywności i uprzednich uprawnień ma oddzielne ograniczone wkłady.
Obecna integracja produkcyjna oznacza je jako unknown i przyznaje zero punktów.
Dowolne pola logu lub notatki nie ustanawiają zaufanej reputacji ani historii.
Czysty podgląd może sprawdzić jawne wejście kontekstowe; nie zapisuje wyników
w rzeczywistych alertach i incydentach.

Każde zapisane obliczenie przechowuje wersję/hash polityki, snapshot i hash
wejścia, źródłowe identyfikatory, składniki i ich przyczyny, raw score,
clipping oraz wynik. Poprzednich obliczeń nie edytujemy ani nie usuwamy.
Bieżący wynik jest projekcją konkretnego obliczenia. Odczyt API nie przelicza
i nie zapisuje stanu. Jawny, ograniczony backfill obsługuje starsze rekordy.
Nowy wynik, projekcja i audyt współdzielą transakcję; retry identycznego wejścia
nie dopisuje kolejnych kopii.
PostgreSQL ogranicza zapis projekcji i sprawdza jej zakres, aktualną rewizję
oraz odniesienia do dowodów. Arytmetykę oblicza zaufany moduł aplikacji.
Append-only nie uwierzytelnia autora nowego wpisu przeciw przejętemu runtime
z dostępem INSERT; jest to ta sama granica zaufania co zapis alertów i audytu.

## Alternatywy

Sumowanie score alertów premiowałoby duplikaty i liczbę nazw reguł.
Losowe albo stałe demo scores nie wyjaśniałyby zaobserwowanych danych.
Przyjęcie confidence=100 dla wszystkich reguł pomyliłoby politykę wag
z pomiarem pewności. Przeliczanie przy GET tworzyłoby ukryte mutacje
i utrudniało powtarzalność odczytu.

## Konsekwencje

Zmiana aktywnego dowodu może obniżyć wynik; historia zachowuje wcześniejszą
ocenę. Poziom risk może różnić się od severity i statusu analityka.
Brak kontekstu jest widoczny i nie oznacza braku zagrożenia.
Rozwinięcie przyszłych źródeł kontekstu wymaga ich pochodzenia i daty snapshotu;
zmiana wag albo zasad deduplikacji wymaga nowej wersji polityki.

## Dowód akceptacji i ponowne rozważenie

Bramka: ręcznie policzone wektory, granice progów, overlap/duplikaty,
scope, niezmienność snapshotów, rollback, konkurencyjne retry, uprawnienia,
zmiana false-positive i odpięcie dowodu oraz zgodność API/panelu.
Wykonane wyniki i granice dowodu opisuje [raport Etapu 3](../validation-risk.md).
Wagi wymagają ponownego przeglądu po rzeczywistej kalibracji scenariuszy
lub wprowadzeniu IOC, inventory, ATT&CK i historii verdictów.
