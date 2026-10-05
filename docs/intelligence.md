# Etap 7 — lokalne Threat Intelligence i IOC

Lokalny katalog wskaźników IP, domain, URL i hash działa w PostgreSQL,
w istniejącym API i detektorze. Panel umożliwia odczyt, dokładne sprawdzenie,
tworzenie, wersjonowaną zmianę metadanych, wyłączenie i import JSON.
Każda rewizja ma reputację unknown/clean/suspicious/malicious, nullable
confidence 0–100, wymagane źródło, first/last seen, tagi oraz opis.
Są to deklaracje źródła, a nie potwierdzenie ataku ani skalibrowane prawdopodobieństwo.
[Decyzja](adr/0013-local-intelligence.md), [walidacja](validation-intelligence.md).

## Tożsamość i rewizje

Tożsamość jest unikalna według typu i kanonicznej wartości.
Wartości istniejącego IOC nie zmienia się: inna wartość to nowy wskaźnik.
Metadane i active zmienia się przez nową niezmienną rewizję.
Nie ma hard delete ani publicznej dowolnej aktualizacji bazy.
Limit: 1000 tożsamości łącznie z wyłączonymi, 50 rewizji na IOC,
100 rekordów na atomowy import. Każdy rekord ma maksymalnie 16 tagów,
źródło 128 znaków i opis 2048 znaków. Dokumenty/hash są weryfikowane przy odczycie.

Zmiany wymagają intelligence:manage (manager/admin), blokady wspólnej
z publikacją detekcji i ponownej kontroli uprawnień po oczekiwaniu.
PATCH wymaga If-Match; konflikt 412 wymaga odświeżenia, zachowując szkic.
Intelligence:read umożliwia odczyt katalogu, historii, providerów i lookup.
Analyst ma intelligence:propose w macierzy przyszłych możliwości, ale ten etap
nie dostarcza endpointu propozycji. UI udostępnia mu obecne odczyty.

Import to `{"items":[{"type":"ip","value":"192.0.2.1","source":"własna analiza"}]}`.
Rekord domyślnie ma unknown, confidence null, active true. Dokładnie identyczny
istniejący rekord jest no-op; odmienne metadane wymagają jawnego PATCH.
Duplikaty kanoniczne w jednej partii są odrzucane. Błąd lub brak audytu wycofuje
całą partię. Body importu do 1 MiB; inne mutacje do 64 KiB, z kontrolą JSON
depth, duplikatów kluczy i wartości niefinitywnych.

## Normalizacja `ioc-normalization-v1`

| Typ | Reguła dokładnego klucza |
| --- | --- |
| IP | Kanoniczny IPv4/IPv6; bez CIDR, strefy, liczby całkowitej. Mapped IPv6 nie staje się IPv4 |
| Domain | IDNA2008/UTS46 nontransitional, małe litery, opcjonalna jedna końcowa kropka; pełna nazwa DNS. Bez wildcard, adresu IP, pojedynczego labelu i liczbowego TLD |
| URL | Tylko http/https, kanoniczny host, port domyślny usunięty, pusty path `/`, percent hex uppercase. Zachowane path/query/fragment, kolejność query, dot segments i puste delimitery `?`/`#`. Bez userinfo, backslash i niepoprawnego portu/escape |
| Hash | MD5/SHA1/SHA256/SHA512 według długości albo jawnego prefiksu, lowercase `algorithm:hex`. Wielohashowe listy nie są interpretowane |

Ekstrakcja czyta wyłącznie typowane pola source.ip, destination.ip,
http.url, http.referrer, host poprawnego URL/referrer jako domain albo IP,
process.hash i file.hash. Nie wyszukuje tekstu w raw_event, command line,
extensions ani host.name. Obecny schemat normalized 1.0 nie ma network.domain.
Niepoprawne lub nieobsługiwane pole jest pomijane, bez obcinania wartości.
Kanoniczny IOC ma maksymalnie 2048 znaków; oryginalny URL dowodu do 8192.

URL są tekstem w UI. System nie pobiera ich, nie rozwiązuje DNS, nie otwiera
stron, nie wysyła IOC do zewnętrznego dostawcy. Provider interface jest
rozszerzalny, a `/providers` uczciwie zwraca wyłącznie dostępny lokalny provider.
Etap nie zawiera zewnętrznego API, kluczy usług, demo IOC ani fikcyjnych ocen.

## Utrwalone dopasowanie i alert

Detektor w jednej transakcji z checkpointem, alertem, ryzykiem i audytem
weryfikuje raw i normalized source proof, porównuje aktywny lokalny katalog
i zapisuje receipt oraz do 32 dokładnych field matches. Receipt powstaje
także dla wyniku zero. Retry używa pierwszej analizy; nie wybiera nowych rewizji.
Każdy match zawiera pole, observed/canonical value, pełną oryginalną rewizję
oraz jej hash. Odczyt sprawdza również typed extraction i oryginalny event.

Reguła `ti:malicious-indicator`, wersja 1.0.0, evaluator intelligence-match-v1,
tworzy jeden medium alert dla zdarzenia z co najmniej jednym malicious match.
Wbudowane i Sigma detekcje nadal działają; IOC kontekst wzbogaca ich ocenę.
Reguła TI nie przypisuje rodziny zachowania ani technik MITRE. Dopasowanie
jest kandydatem do analizy i nie potwierdza ataku. Medium TI samo nie tworzy
automatycznego incydentu; analityk może dołączyć alert do sprawy.

GET `/events/{event_id}` wymaga również events:read. Zwraca pending albo
evaluated, także evaluated z pustą listą. Nigdy nie analizuje ponownie danych.
Administrator może jawnie wykonać jedną partię backfill do 100 starszych
normalized events **bez receipt**; przycisk panelu wykonuje 25. Backfill
nie nadpisuje istniejących wyników, nie resetuje DetectionJob, nie tworzy
historycznych alertów i nie przelicza istniejącego ryzyka. Późniejsza jawna
recalculation istniejącego alertu/sprawy może użyć nowego indeksu i zapisać
nową historyczną ocenę. Import i PATCH nie uruchamiają backfill/recalculation.

Replay receipt należy do dokładnego event/dataset/run. Pierwsza analiza
korzysta z katalogu dostępnego **wtedy**, bez twierdzenia, że reputacja była
znana w historycznym czasie eventu. Nowy run może użyć innej rewizji.

## Ryzyko `risk-policy-v4`

| Kwalifikująca reputacja źródła | Wkład I |
| --- | --- |
| Malicious, confidence co najmniej 80 | 15 |
| Malicious, confidence niższe albo nieznane | 5 |
| Suspicious, confidence co najmniej 50 | 8 |
| Suspicious poniżej progu albo confidence nieznane | 0 |
| Clean / unknown | 0 |

Wartości nie sumują się: maksimum I=15. Fakty muszą mieć wersjonowany dowód,
kwalifikujące się event references, zgodny subject i ważność. Produkcyjny
builder weryfikuje oryginalny event, zakres, receipt i rewizję. Clean nie
odejmuje punktów i nie oznacza potwierdzonego bezpieczeństwa. Deklaracja
confidence IOC pozostaje odrębna od nieznanego confidence samej detekcji.
Stałe medium TI daje D30, bez C/E premii za zachowania ani liczbę zdarzeń.

Wejście zachowuje do 100 najwyżej punktujących field matches, jawnie podając
available/selected/truncated i porządek wyboru. To ogranicza payload i zachowuje
dokładne maksimum I. Starsze v2/v3 oceny, hashe i arytmetyka pozostają zachowane;
brak IOC kontekstu/TI baseline nadal wybiera v3. Odczyt nie zmienia oceny.
W profilu encji najwyższe istniejące ryzyko może wskazywać v4.

Lista katalogu korzysta z jednej migawki zapytania dla count/page.
Cursor jest podpisany i powiązany z principal/path/filters oraz timestamp anchor.
Timestamp nie stanowi commit timestamp ani wspólnej migawki różnych stron;
metadane bieżącej rewizji mogą zmienić filtr między kolejnymi odczytami.
