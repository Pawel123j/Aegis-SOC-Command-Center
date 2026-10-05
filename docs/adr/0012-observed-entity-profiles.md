# ADR 0012 — profile obserwowanych encji

Data: 2026-10-04. Status: przyjęta; implementacja i regresja ukończone 2026-10-05.
Rozszerza ADR 0002, 0008 i 0009. [Zakres](../entities.md).

## Kontekst

Analityk potrzebuje historii hosta, konta, IP i procesu obejmującej logi,
alerty oraz sprawy. Wspólna nazwa konta, PID lub adres NAT nie jest stabilnym
identyfikatorem osoby lub instancji. Logi są twierdzeniami źródła;
nie dysponujemy jeszcze zweryfikowanym CMDB ani katalogiem tożsamości.
Wiele zdarzeń korelacji wymaga uwzględnienia także dowodów poza kotwicą.

## Decyzja

Tworzymy osobną politykę `entity-identity-v1` i append-only indeks w PostgreSQL.
Klucz zawiera rodzaj, namespace live lub dokładny replay oraz konserwatywną
podstawę identyfikacji. Wersja polityki jest częścią klucza. Nazwy nie stają
się aliasem silniejszego identyfikatora bez odrębnej decyzji analitycznej.
Źródło i host ograniczają identyfikację tam, gdzie lokalne konta lub instancje
mogłyby się pokrywać. Sam PID pozostaje lokalny dla eventu.

SID jest walidowany strukturalnie: revision 1, 48-bit authority, do 15
32-bit subauthorities. Opisują to pierwotne źródła Microsoft:
[SID Components](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components)
i [SID Packet Representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861).
Własna konserwatywna polityka rozpoznaje pełne SID kont jako podstawę w jednym
źródle; powtarzalne SID systemowe/grup wymagają hosta albo event-local.
To wybór aplikacji, nie weryfikacja konta przez Microsoft lub domenę.

Normalized snapshot, encje, obserwacje i receipt powstają w jednej transakcji.
Publikacja alertu dopisuje odwołania do wszystkich zweryfikowanych dowodów.
Ograniczony, audytowany backfill uzupełnia indeks starszych danych bez zmiany
ich treści. GET pozostaje odczytem. Receipts obejmują także puste ekstrakcje.
Runtime ma SELECT/INSERT do indeksu; nie ma UPDATE/DELETE. Zaufany autor INSERT
pozostaje granicą systemu, a append-only nie chroni przed fałszywym nowym wpisem
w przypadku przejęcia całego runtime.

Ryzyko encji wskazuje maksymalną aktualną ocenę kwalifikującego się alertu
w zakresie. Nie powstaje nowy scoring ani źródło krytyczności/privileges.
Wyjaśnienie pochodzi z istniejącego obliczenia. False positive pozostaje
w historii, lecz nie w risk/MITRE. Sprawy liczą aktywne powiązania.
MITRE pozostaje candidate association, nie potwierdzeniem ataku.

## Alternatywy

Łączenie wyłącznie po nazwie konta sklejałoby lokalnych administratorów.
Wspólny PID mógłby opisywać kolejne procesy. Agregacja samych kotwic alertów
gubiłaby wcześniejsze dowody sekwencji. Suma ocen pokrywających się alertów
zawyżałaby ryzyko. Nieograniczony backfill w migracji opóźniałby start oraz
utrudniał kontrolę błędów historycznego proof.

## Konsekwencje

Jedna osoba może mieć oddzielne profile nazwy i SID; niepełne dane mogą dać
jednozdarzeniowy profil procesu. Panel wyjaśnia podstawę identyfikacji.
Stara baza wymaga jawnego indeksowania partiami, a status pokazuje niepełność.
Paginacja i ograniczone okno zapobiegają bezgranicznym odpowiedziom;
liczniki SQL obejmują cały zakres, nie tylko wyświetloną stronę.
Pierwotna korelacja oraz historyczne oceny zachowują dotychczasowe klucze.

## Dowód akceptacji i ponowne rozważenie

Wymagane: przypadki false joins i izolacji live/replay, atomowy zapis/retry,
upgrade/backfill/granty/downgrade, wszystkie contributed events, uprawnienia
po blokadzie, podpisane kursory, rzeczywiste liczniki/risk/FP/MITRE oraz UI.
Wyniki zapisuje [raport Etapu 6](../validation-entities.md).
Rejestr inwentarza, aliasy, centralna tożsamość lub własna polityka entity risk
wymagają osobnej decyzji i wersji kontraktu; nie są skutkiem samego profilu.
