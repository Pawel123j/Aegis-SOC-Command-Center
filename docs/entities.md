# Profile encji — Etap 6

Stan 2026-10-05: implementacja i wspólna regresja ukończone. Baseline `44179d9`.
Wyniki uruchomienia i granice dowodu zapisano w [raporcie](validation-entities.md).
[Decyzja o tożsamości](adr/0012-observed-entity-profiles.md).

## Zakres profilu

Host, użytkownik obserwowany w logu, adres IP i proces mają historię aktywności,
powiązane alerty i sprawy, first/last seen w wybranym oknie oraz wyjaśnione
ryzyko. Profil obejmuje też role w zdarzeniach, nieudane logowania,
powiązane hosty i kandydackie skojarzenia MITRE. Konto w logu nie jest kontem
operatora panelu. Współwystępowanie hosta i konta nie potwierdza własności hosta.

Źródłem są niezmienne normalized snapshots PostgreSQL. ClickHouse pozostaje
projekcją wyszukiwania; profile nie wymagają nowej usługi ani zależności.
Lista aktywności profilu działa na PostgreSQL. Otwarcie pełnego zdarzenia
korzysta z dotychczasowego archiwum ClickHouse i może zgłosić brak projekcji
lub jego niedostępność. Pełne zachowane dowody alertu są w PostgreSQL.
Nowe obserwacje powstają w transakcji normalizacji. Odwołania do wszystkich
zdarzeń alertu powstają w transakcji publikacji alertu, także dla korelacji.
Indeks jest append-only. Odczyt nie dopisuje ani nie odtwarza danych.

## Tożsamość i granice obserwacji

Polityka `entity-identity-v1` rozdziela zakres live oraz dokładny replay
dataset/run. Kanoniczny klucz obejmuje rodzaj encji, zakres i podstawę
identyfikacji; jego hash i deterministyczny UUID pozostają stabilne przy retry.
Pierwotne klucze korelacji i historyczne oceny ryzyka zachowują swoje kontrakty.

- Host: źródło i nieprzezroczysty identyfikator; nazwa jest słabszą podstawą
  zastępczą. Nie stanowi wpisu zweryfikowanego inwentarza.
- Użytkownik: aktor i konto docelowe mają osobne role. Rozpoznany kompletny SID
  konta może łączyć obserwacje w jednym źródle. Powtarzalne SID systemowe,
  UID i nazwy wymagają hosta, a przy jego braku pozostają lokalne dla zdarzenia.
  Nazwa i SID nie są automatycznie łączone w alias. Wielkość liter zależy od
  rodzaju źródła; identyfikatory nie są arbitralnie zmieniane na małe litery.
- IP: kanoniczny adres w zakresie live lub replay. Wspólny adres, NAT lub proxy
  nie świadczą o wspólnej osobie lub urządzeniu. Źródło i cel mają osobne role.
- Proces: identyfikator instancji wraz z hostem i źródłem. Sama nazwa lub PID
  daje tożsamość lokalną dla zdarzenia, aby ponowne użycie PID nie sklejało
  różnych uruchomień. Brakujące fakty nie tworzą encji o nazwie Unknown.

Pola pochodzą z obserwacji źródła. `inventory_verified=false` i podstawa
identyfikacji są jawne. Nie przypisujemy privilege/asset criticality ani
skalibrowanego confidence tylko na podstawie nazwy administratora.

## Ryzyko, alerty i MITRE

Ryzyko profilu jest projekcją najwyższej aktualnej oceny kwalifikującego się
alertu w oknie, z odwołaniem do jego istniejącego obliczenia i wyjaśnienia.
Nie tworzy nowej polityki ani obliczenia encji. Nie sumuje ocen alertów lub
incydentów, których dowody się pokrywają. Brak oceny daje null.
Alerty false positive pozostają w historii i mają osobny licznik; nie
uczestniczą w ryzyku ani kandydackich skojarzeniach MITRE.

Powiązanie alertu uwzględnia każde zweryfikowane contributed event,
a nie tylko kotwicę. Sprawy korzystają z aktywnych powiązań alertu;
odłączone powiązania nie zwiększają liczników. Zamknięte sprawy pozostają
częścią historii. Nieudane logowania liczą distinct event z kategorią
authentication i outcome failure powiązany z encją, niezależnie od jej roli.
Obecność encji jako aktora, celu lub hosta nie przypisuje jej własnych prób
logowania. First/last seen odnoszą się do czasu zdarzenia w wybranym oknie.

## Zakres zapytań i starsze dane

Wspólne filtry: live lub dokładny replay dataset/run, UTC `from`/`to`, rodzaj,
literalne wyszukiwanie i limit 1–100. Domyślne okno ma 30 dni; maksymalne
366 dni. Przedział jest półotwarty `[from,to)` względem czasu contributed
event. Paginacja używa podpisanego kursora powiązanego z filtrami i zasobem.
Liczby obejmują cały wybrany zakres; widoczna strona nie jest ich mianownikiem.
Cursor zachowuje kotwicę filtrującą zapisane czasy utworzenia i indeksowania.
Nowe wyszukiwanie/odświeżenie otrzymuje nową kotwicę. Każda odpowiedź korzysta
ze spójnego snapshotu zapytania, lecz osobne strony nie utrwalają wspólnego
snapshotu PostgreSQL. Transakcja ze znacznikiem sprzed kotwicy zatwierdzona
później może pojawić się na kolejnej stronie. Bieżąca decyzja o false positive,
powiązanie sprawy i ocena również mogą zmienić się pomiędzy żądaniami.
Zapytania PostgreSQL mają limit czasu 3 s.

Starsze normalized events i alerty wymagają jawnego backfillu administratora:
jedno żądanie obejmuje do 100 zdarzeń oraz do 100 alertów, dodatkowo z budżetem
100 dowodów alertowych. Alert oczekuje, aż jego zdarzenia będą zaindeksowane;
nie dopisuje poza budżetem dodatkowych eventów. Receipts zapisują
również zdarzenia bez rozpoznanych encji. Retry nie dopisuje duplikatów.
Mutacja i audyt są atomowe, a uprawnienie jest sprawdzane ponownie po blokadzie.
Panel pokazuje liczbę oczekujących rekordów; niepełny indeks nie potwierdza
braku wcześniejszej aktywności. Nowe rekordy są indeksowane od razu.

Wszystkie odczyty wymagają jednocześnie events:read, alerts:read i incidents:read.
Backfill wymaga system:manage. Szczegółowy kontrakt i wyniki są w
[API](api-contract.md) i [walidacji](validation-entities.md).
