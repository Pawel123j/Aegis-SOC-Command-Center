# MITRE ATT&CK — Etap 4

Data: 2026-10-03. Stan: Etap 4 zaimplementowany, zweryfikowany i uruchomiony.
Punkt wyjścia: `ead4ac6`, ukończony Risk Engine.
[Plan rozbudowy](soc-expansion-plan.md),
[decyzja](adr/0010-versioned-attack-mappings.md).

## Audyt i plan przyrostu

Repozytorium ma oddzielne moduły detekcji, korelacji, alertów, incydentów
i ryzyka. Trzy reguły pojedynczego zdarzenia i pięć korelacji zawierają już
identyfikatory technik. Nie istnieje jeszcze lokalny katalog nazw/taktyk,
walidowana wersja mapowania ani widok pokrycia. Incydent zbiera identyfikatory
z aktywnych alertów; oryginały reguł i zdarzeń są niezmienne w PostgreSQL.
ClickHouse jest projekcją wyszukiwania. API stosuje jawne permissions;
panel React używa rzeczywistych API i usuwa stan po zmianie tożsamości.
Dotychczasowy dowód Etapu 3: 1004 testy backendowe i 59 frontendowych.

Plan:

1. Utrwalić lokalnie metadane oficjalnego Enterprise ATT&CK v19.2,
   ze źródłem, hashem i atrybucją; walidować identyfikatory oraz relacje.
2. Dodać oddzielne niezmienne snapshoty mapowań nowych alertów i indeksowane
   skojarzenia technique/tactic, w tej samej transakcji co alert i audyt.
3. Udostępnić katalog, jawne mapowania reguł/szczegółów i agregacje rzeczywistych
   alertów oraz aktywnie powiązanych incydentów.
4. Dodać widok pokrycia i czytelne nazwy w szczegółach.
5. Wykonać nowe testy i całą regresję, migrację oraz kontrolę uruchomienia;
   zapisać raport w dziewięciu punktach i osobny Conventional Commit.

Reguły, ich snapshoty i dotychczasowe oceny ryzyka pozostają zgodne.
Nowe pola metadanych API są odrębne od snapshotu używanego przez Risk Engine.
Ten etap nie zamyka historycznej PHASE 8: pełny graf/storyline i filtry
wyszukiwania zdarzeń będą osobnymi przyrostami.

## Katalog i znaczenie mapowania

Katalog pochodzi z oficjalnego repozytorium
[ATT&CK STIX 2.1](https://github.com/mitre-attack/attack-stix-data).
Wydanie v19.2 jest przypięte do commita
`6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`; aktualność wydania sprawdzono
w [oficjalnych aktualizacjach MITRE](https://attack.mitre.org/resources/updates/).
Runtime korzysta z lokalnych danych i nie pobiera katalogu z Internetu.
Metadane obejmują również historyczne revoked/deprecated wpisy; nowe mapowania
mogą używać wyłącznie aktywnych technik i poprawnych relacji do aktywnych taktyk.
Historyczny brak relacji do parent nie jest uzupełniany domysłem.

Mapowanie jest `candidate_association`. Wskazuje zgodność rodzaju zachowania
z techniką oraz taktyki powiązane z nią w oficjalnym katalogu. Nie potwierdza
złośliwego zamiaru, skutecznego ataku ani realizacji wszystkich tych taktyk.
T1059.001 ma powiązanie z Execution; technika może mieć więcej taktyk.
Nazwa taktyki pochodzi z przypiętego wydania, a nie z historycznej listy nazw.
Otwarcie sesji root/su pozostaje bez mapowania: sam ten log nie dowodzi
nadużycia sudo ani techniki T1548.003.

Katalog nie daje automatycznie punktów składnika T w Risk Engine.
Zweryfikowane powiązanie catalogue technique→tactic nie ustanawia dowodu
zrealizowania taktyki. Dotychczasowe scores i ich wyjaśnienia pozostają ważne.

## Utrwalanie

Nowy alert otrzymuje oddzielny snapshot z wersją i hashem katalogu,
wersją polityki mapowań, źródłową regułą i nazwami technik/taktyk.
Znormalizowane skojarzenia służą wyłącznie do indeksowanych agregacji.
Runtime ma SELECT/INSERT, bez UPDATE/DELETE/TRUNCATE historycznych mapowań.
Zaufany writer aplikacji odpowiada za prawidłowość nowego wpisu;
append-only nie uwierzytelnia INSERT po przejęciu tego writera.

Istniejący alert bez nowego snapshotu jest jawnie historyczny/niezmapowany.
Odczyt nie dopisuje snapshotów i nie przepisuje oryginalnego `rule_snapshot`.
Incydent pokazuje projekcję aktywnych, kwalifikujących się alertów wraz
z ich pochodzeniem; odpięte dowody pozostają w dotychczasowej historii.

## Zasady liczników

Domyślny zakres to live z ostatnich 30 dni według `event_timestamp` alertu.
Przedział jest półotwarty: `from <= event_timestamp < to`, w UTC,
maksymalnie 366 dni. Replay wymaga dataset i run, aby nie łączyć przebiegów.
False positive jest domyślnie wykluczony; jawna opcja pozwala go uwzględnić.
Resolved alert i zamknięta sprawa nadal reprezentują zachowane dowody.

Licznik alertów oznacza distinct alert IDs. Licznik incydentów oznacza distinct
incident IDs z aktywnym powiązaniem do alertu kwalifikującego się w tym zakresie.
Wiele alertów tej samej techniki w jednej sprawie daje jeden incydent.
Technika może mieć kilka taktyk, więc suma wierszy nie jest licznikiem całości.
Brak/nieobsługiwane mapowanie pozostaje jawne, a nie wypełnia pokrycia.

Pokrycie skonfigurowanych reguł i ich aktualnego enabled jest oddzielone od
zaobserwowanych alertów. Wyłączenie reguły nie usuwa wcześniejszych wyników.
Agregacje odnoszą się do jednej wersji katalogu, mają ograniczenia czasu,
limit żądań oraz spójny odczyt. Endpoint nie pobiera wszystkich surowych dowodów.

## Uprawnienia i panel

Katalog wymaga `detections:read`. Pokrycie wymaga jednocześnie
`detections:read`, `alerts:read` i `incidents:read`; panel stosuje tę samą bramkę.
Szczegóły używają uprawnień swojego alertu lub incydentu.
Frontend prezentuje wersję katalogu, zakres, zasady liczników, brak mapowania,
loading/error/empty oraz odrzuca spóźnione odpowiedzi po zmianie kontekstu.
GET `/api/v1/mitre/catalog` zwraca aktywne metadane i pochodzenie katalogu.
GET `/api/v1/mitre/coverage` ma filtry mode/from/to/dataset_id/run_id/
include_false_positives. Nowe `mitre_mapping` w regułach i szczegółach nie jest
częścią oryginalnego `rule_snapshot`. Projekcja sprawy pomija false-positive
i nieaktywne links; kompatybilne stare `mitre_techniques` zachowuje dawną semantykę.
Dokładne DTO opisuje [kontrakt API](api-contract.md).

Panel domyślnie pokazuje techniki skonfigurowane lub zaobserwowane. Można
przeszukać pełny aktywny katalog, wybrać taktykę i stronicować wynik.
Pochodzenie zawiera oficjalne źródło, licencję, wersję i SHA-256.
Katalog ma 15 aktywnych taktyk, 697 aktywnych technik i 161 historycznych
revoked/deprecated wpisów; artefakt ma 446 846 bajtów i SHA-256
`afc5aec04660aa0f1f2ed495247239002695574735a57133529803f08946a339`.
Ekstraktor offline odtwarza te same bajty, sprawdzając hash źródła i licencji.
[Instrukcja odtworzenia i atrybucja](../backend/app/modules/mitre/data/README.md).
[Wyniki walidacji i ich granice](validation-mitre.md).
