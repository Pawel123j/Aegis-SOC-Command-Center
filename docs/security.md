# Model bezpieczeństwa aplikacji

Status: **projekt PHASE 0, bez implementacji**. Poniższe mechanizmy są wymaganiami dla kolejnych faz i nie stanowią deklaracji, że obecne repozytorium je realizuje. Zakres pierwszego wydania to jedna organizacja SOC i lokalne demo Docker Compose. Wystawienie do Internetu, SSO, MFA, wielodostępność i formalna zgodność nie są objęte tym modelem.

## Zasoby i granice zaufania

Chronimy konta analityków, sesje, logi i dane osobowe, reguły detekcji, integralność incydentów, evidence, audyt i dostępność pipeline. Każdy log, IOC, tekst reguły, notatka i wynik parsera jest niezaufaną treścią, nawet jeżeli pochodzi z generatora demo.

Przeglądarka komunikuje się z API przez jeden origin reverse proxy. Bazy i Redis nie udostępniają portów na hoście w zwykłym profilu Compose. API sprawdza tożsamość i uprawnienia; ukrycie przycisku w React nie jest kontrolą dostępu. Workery otrzymują identyfikatory operacji, a dane i stan odczytują z PostgreSQL. ClickHouse obsługuje analitykę, a Redis transport zadań; żaden z nich nie rozstrzyga o rolach użytkownika, audycie ani stanie wykonania playbooka.

| Zagrożenie / wejście | Skutek | Projektowana kontrola | Dowód wymagany przed odbiorem |
| --- | --- | --- | --- |
| Skradziony token, brute force logowania | Przejęcie konta | Krótka sesja dostępu, rotacja refresh, unieważnianie, limity prób | Test wygaśnięcia, replay i zmiany roli |
| Log z HTML/JS, notatka, tytuł reguły | Stored XSS w konsoli SOC | Renderowanie tekstu, CSP, brak surowego HTML | Złośliwy payload widoczny jako tekst w UI |
| CSRF przeciwko refresh/logout/login | Wymuszenie operacji na sesji | Dokładny origin, synchronizer token, SameSite | Odrzucenie obcego i brakującego origin oraz tokena |
| Podmiana ID / bezpośrednie wywołanie API | Ominięcie RBAC | Permission policy po stronie API, kontrola obiektu | Macierz 401/403 i testy wszystkich mutacji |
| Query, Sigma YAML, dane parsera | Injection, deserializacja, DoS | AST, parametry, allowlist, bezpieczny loader, limity | Przypadki injection, YAML tags/alias expansion, głęboki AST |
| Duplikaty, restart, wyścig workerów | Podwójny alert lub efekt SOAR | Inbox/outbox, unikalne klucze, fencing, transakcje | Test restartu po commicie przed ACK |
| Playbook z adresem URL lub komendą | SSRF, wykonanie kodu, realna zmiana infrastruktury | Zamknięty rejestr akcji, brak shell/HTTP connectorów, tryb simulation | Test odmowy nieznanej akcji i braku egress |
| Zmiana/usunięcie audit log | Utrata historii | Osobna rola migracyjna, INSERT/SELECT bez UPDATE/DELETE/TRUNCATE | Próby modyfikacji jako rola runtime kończą się odmową |
| Zalew ingestion/hunt, kosztowny hash hasła | Wyczerpanie zasobów | Limity rozmiaru, tempa, współbieżności, timeout i backpressure | Przekroczenia dają 413/429/503 bez utraty przyjętych eventów |
| Ujawnienie sekretów w logach i Git | Przejęcie usług | Sekrety generowane lokalnie, redakcja, skan repo, bezpieczne błędy | Skan repo i test odpowiedzi/logów |

## Uwierzytelnianie i sesje

- Hasła: Argon2id z losową solą biblioteki; minimalny punkt startowy `m=19456 KiB`, `t=2`, `p=1`, następnie pomiar kosztu na docelowym sprzęcie. Parametry przechowywane z hashem; rehash przy poprawnym logowaniu po zmianie polityki. Hasła 15–128 znaków, bez obcinania i arbitralnych reguł typu obowiązkowy znak specjalny. Dobór minimum Argon2id opiera się na [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- JWT access: ważność 5 minut, przesyłanie wyłącznie `Authorization: Bearer`, przechowywanie w pamięci przeglądarki, bez localStorage/sessionStorage i bez cookie. Weryfikacja ustalonego algorytmu `HS256`, podpisu, `iss`, `aud`, `sub`, `exp`, `iat`, `jti`, `sid`; odrzucenie `none`, obcego algorytmu i tokenów innego typu. Losowy klucz min. 32 bajty, osobny dla środowiska. Algorytm nie pochodzi z dowolnej wartości podanej przez klienta.
- JWT nie jest samodzielnym źródłem uprawnień: API sprawdza aktywność konta i sesji oraz aktualną rolę w PostgreSQL. Wylogowanie, dezaktywacja i zmiana roli mają działać bez czekania na `exp`. Awaria tego sprawdzenia daje 503, bez domyślnego zezwolenia.
- Refresh: nieprzewidywalny opaque token z 32 losowych bajtów; w PostgreSQL tylko SHA-256 tokena, rodzina sesji, daty, status użycia i unieważnienia. Token jednorazowy, rotowany atomowo pod blokadą wiersza. Ponowne użycie zużytego tokena unieważnia całą rodzinę; zużyte hashe zachowujemy do końca maksymalnego okresu sesji. Wartość hasha nie jest tokenem akceptowanym przez API.
- Sesja: 12 godzin bezczynności i 7 dni maksymalnie od logowania; rotacja nie przesuwa limitu absolutnego. Zmiana hasła unieważnia wszystkie sesje. UI wykonuje najwyżej jeden refresh naraz, także między kartami przez Web Locks/BroadcastChannel; ścisła polityka replay może przy wyścigu wymusić ponowne logowanie.
- Refresh cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, host-only bez `Domain`, `Path=/api/v1/auth`. API nigdy nie zwraca refresh tokena w JSON. Ścieżka cookie ogranicza wysyłanie, ale nie zastępuje autoryzacji. Odpowiedzi auth mają `Cache-Control: no-store`.

Rotacja ogranicza możliwość powtarzanego użycia wykradzionego refresh tokena. Jest to wykorzystanie zalecenia opisanego w [RFC 9700, sekcja 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14), a nie deklaracja implementacji pełnego serwera OAuth/OIDC. Token access w pamięci nie chroni przed aktywnym XSS; zabezpieczenia renderowania pozostają niezbędne.

## CSRF i lokalny profil demo

Przeglądarka rozpoczyna sesję od `GET /api/v1/auth/csrf`. API tworzy krótkotrwałą sesję pre-auth z identyfikatorem w HttpOnly cookie i zwraca synchronizer token w JSON. Po logowaniu wymienia go na token związany z rodziną sesji. Token pozostaje w pamięci UI, nie w URL i nie w logach. Reload pobiera go ponownie poprzez same-origin endpoint związany z cookie. `POST` login, refresh i logout wymagają `X-CSRF-Token` oraz dokładnego `Origin` zgodnego ze skonfigurowanym originem. Brak lub `null` origin daje odmowę w przepływie przeglądarkowym; klient maszynowy korzysta z osobnego credential ingestion.

Nie zezwalamy na credentialed CORS z dowolnych domen ani na mutacje przez GET. Endpointy JSON odrzucają form-urlencoded/text/plain. `SameSite` stanowi dodatkową warstwę, a nie jedyny warunek. Model tokena synchronizowanego i weryfikacja origin wynikają z [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Domyślna konfiguracja bezpieczeństwa wymaga HTTPS. Jawnie wybrany profil lokalnego demo może korzystać z HTTP wyłącznie na loopback `127.0.0.1`/`localhost`, z `Secure=false` i osobną nazwą cookie. Profil nie jest konfiguracją wdrożeniową; start z tym wyjątkiem i originem innym niż loopback musi zakończyć się błędem. HSTS włączamy w profilu HTTPS, nie w lokalnym HTTP. Dokładne działanie cookie musi być zweryfikowane E2E w przeglądarce.

## RBAC

Każdy endpoint ma nazwaną permission i domyślnie odmawia dostępu. Role ludzkie nie zastępują credential źródła. System działa w jednej organizacji; nie deklarujemy izolacji tenantów.

| Operacja | Admin | SOC Manager | SOC Analyst | Read Only |
| --- | --- | --- | --- | --- |
| Odczyt eventów, alertów, incydentów, IOC, reguł i wyników | Tak | Tak | Tak | Tak |
| Uruchomienie ograniczonego zapytania ad hoc | Tak | Tak | Tak | Tak |
| Zapis hunt, bookmark, investigation | Tak | Tak | Tak | Nie |
| Edycja otwartego incydentu, notatki, evidence, IOC link | Tak | Tak | Tak | Nie |
| Przypisanie incydentu | Dowolny aktywny operator | Dowolny aktywny operator | Tylko przypisanie siebie | Nie |
| Zamknięcie / false positive z uzasadnieniem | Tak | Tak | Tak | Nie |
| Reopen zamkniętego incydentu | Tak | Tak | Nie | Nie |
| Draft i test detekcji | Tak | Tak | Tak | Nie |
| Import Sigma, publikacja/aktywacja reguł | Tak | Tak | Nie | Nie |
| Kuracja lokalnej bazy IOC | Tak | Tak | Tylko propozycja | Nie |
| Edycja, publikacja i wyłączenie playbooka | Tak | Tak | Nie | Nie |
| Start/anulowanie zatwierdzonego playbooka simulation | Tak | Tak | Tak | Nie |
| Uruchomienie kontrolowanego scenariusza demo (`demo:run`) | Tak | Tak | Nie | Nie |
| Odczyt globalnego audit log | Tak | Tak | Nie | Nie |
| Użytkownicy, role, credential źródeł, konfiguracja | Tak | Nie | Nie | Nie |
| Realne akcje blokowania/izolowania | Nie | Nie | Nie | Nie |
| Zmiana/usunięcie audit przez API | Nie | Nie | Nie | Nie |

SOC Analyst ma dostęp do wszystkich spraw tej organizacji; nie udajemy separacji spraw per owner. Szczegóły operacji użytkowników nie są dostępne przez sam odczyt katalogu operatorów do przypisania. Nie można zdezaktywować ostatniego aktywnego Admina. UI pobiera capabilities, lecz API ponownie sprawdza permission przy każdej operacji, również przy retry i wykonaniu w workerze.

Ingestion używa niezależnego, losowego i hashowanego credential z identyfikatorem źródła, zakresami `events:write` i `events:status`, datą wygaśnięcia i możliwością odwołania. `events:status` pozwala odczytać status tylko własnych batchy w przypisanym source/dataset/mode/run. API przypisuje `source_id` na podstawie credential; payload nie może podszyć się pod inne źródło. Credential nie pozwala wyszukiwać zdarzeń ani logować się do UI. Generator demo używa tego samego kontraktu.

Kontrolowany scenariusz tworzy osobny `dataset_id` z `mode=replay` przez uprawniony launcher. Zewnętrzny nadawca nie ustawia zegara, trybu replay ani cudzej przestrzeni danych. Skończony zestaw wejściowy i przypięte wersje reguł/enrichment pozwalają powtórzyć demo przez ten sam ingestion/inbox/pipeline. Dane demo są oznaczone na obiektach pochodnych i wyłączone z metryk live SOC; izolację wymusza backend, a nie tylko filtr UI.

## Walidacja i ograniczenia

Kontrakty Pydantic odrzucają nieznane pola konfiguracji, niepoprawne typy i nadmierne długości. Batch ingestion ma planowany limit 500 eventów, 1 MiB całego requestu i 64 KiB pojedynczego eventu. Są to wartości startowe do pomiarów, a nie wynik benchmarku. Limity egzekwują proxy i API; odrzucenie zbyt dużego body następuje przed kosztownym parsowaniem. Archiwa i skompresowane body pozostają poza pierwszym zakresem.

Startowe limity: logowanie 5 prób/minutę na parę konto/IP i 30/minutę na IP, refresh 30/minutę na sesję, ingestion 10 requestów/s na źródło, wyszukiwanie 30/minutę i 2 równoległe zapytania na użytkownika, SOAR 5 uruchomień/minutę na operatora. Odpowiedź 429 zawiera `Retry-After`. Identyfikator konta w kluczu limitera jest normalizowany i hashowany. Proxy ufa tylko własnemu proxy nadrzędnemu; dowolny `X-Forwarded-For` klienta nie resetuje limitów. Niedostępny limiter skutkuje 503 na kosztownych i auth endpointach, nie przejściem do trybu bez limitów.

SQL w PostgreSQL i ClickHouse używa parametrów; nazwy kolumn, operatory, sortowanie i funkcje pochodzą z rejestru serwera. [Hunting](threat-hunting.md) opisuje AST i limity. Import Sigma przyjmuje wyłącznie bezpieczny podzbiór YAML: brak tagów obiektów, aliasów/anchors, zduplikowanych kluczy, dołączania plików i zdalnych odwołań; limit 64 KiB, głębokość 16. Nieznany modifier/condition jest błędem, nigdy cichym poszerzeniem detekcji.

Teksty renderujemy jako tekst. Notatki MVP są plain text; bez `dangerouslySetInnerHTML`. Nie pobieramy automatycznie URL IOC, favicon ani zewnętrznych obrazów. CSP ogranicza skrypty i zasoby do własnego originu, bez `unsafe-eval`; `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Dla przyszłych eksportów CSV należy zneutralizować formuły arkusza; sam escaping HTML nie rozwiązuje tego problemu.

## Audyt i least privilege

Audyt zawiera `audit_id`, czas serwera UTC, actor type/id, action, object type/id, wynik, request/correlation ID oraz ograniczony diff przed/po. Zapisujemy logowanie udane/nieudane, logout/replay, odmowy uprawnień, zmiany użytkowników, reguł, playbooków, IOC i spraw oraz wykonania SOAR. Nie zapisujemy haseł, tokenów, cookie, kluczy API ani całych body eventów w logach operacyjnych. Historia evidence przechowuje osobny identyfikator i hash; sam audit nie jest repozytorium plików.

Mutacja domeny, jej audit i outbox powstają w jednej transakcji PostgreSQL. Brak możliwości zapisu audytu powoduje rollback. Nieudane logowanie i odmowa autoryzacji wymagają osobnego krótkiego zapisu audytu, ponieważ nie zatwierdzają mutacji domenowej. Gdy PostgreSQL jest niedostępny, auth zwraca 503, a pozbawiony sekretów log operacyjny informuje o niedostępności audytu.

Rola runtime może tylko `INSERT` i `SELECT` w tabeli audytu, bez `UPDATE`, `DELETE`, `TRUNCATE`, DDL i prawa zmiany ról. Nie jest właścicielem tabel. Migracje uruchamia osobna rola dostępna tylko zadaniu migracyjnemu. Triggery blokujące zmiany mogą stanowić dodatkową ochronę, ale nie zastępują grantów. PostgreSQL rozróżnia te uprawnienia, a właściciel obiektu zachowuje szczególne możliwości; zob. [GRANT](https://www.postgresql.org/docs/current/sql-grant.html).

Append-only dotyczy użytkowników aplikacji i roli runtime. Administrator systemu/DB, backup operator lub osoba z kluczem migracyjnym pozostają zaufanymi uprzywilejowanymi operatorami. Nie deklarujemy odporności na manipulację przez superusera ani niezmienności WORM. Retencja audytu wymaga osobnej udokumentowanej procedury, poza API codziennej pracy.

## Sekrety, zależności i błędy

Właściwe sekrety znajdują się w lokalnym ignorowanym pliku środowiska lub wstrzykiwanym środowisku, nigdy w `.env.example`, obrazie czy Git. Bootstrap ma generować niezależne wartości CSPRNG i jednorazowe dane pierwszego Admina, bez uniwersalnego hasła demo. Start odrzuca brakujące/puste sekrety, znane placeholdery i wartości zbyt krótkie. Sama walidacja długości nie dowodzi losowości; zapewnia ją generator.

Kontenery runtime działają bez root, bez Docker socket, bez uprawnień hosta i bez montowania katalogu domowego. Logi nie ujawniają sekretów, a zewnętrzne API TI nie są potrzebne. Adaptery infrastrukturalne SOAR nie istnieją w rejestrze MVP. Komunikacja z wewnętrznymi bazami pozostaje dozwolona; zakaz sieciowy SOAR dotyczy akcji do celów wskazanych w logach/playbooku i publicznego egress.

Błąd API zawiera stabilny kod, bezpieczny opis i request ID; bez stack trace, SQL i adresów wewnętrznych. Szczegóły trafiają do redagowanych logów. `/health` ujawnia jedynie liveness, `/ready` minimalny wynik gotowości, `/metrics` pozostaje wewnętrzne lub chronione rolą operatorską. Etykiety metryk nie zawierają IP, użytkowników ani event ID. CI ma sprawdzać zależności, sekrety, obrazy i kod, a znane odstępstwa muszą mieć uzasadnienie oraz termin przeglądu.

## Kryteria odbioru implementacji

1. Testy API obejmują każdą mutację i cztery role; brak tokena daje 401, brak permission 403, a obce/nieistniejące ID nie omija polityki.
2. JWT z obcym algorytmem/audience/issuer, wygasły lub ze zdezaktywowaną sesją jest odrzucony. Zużyty refresh powoduje revocation rodziny; test równoległego refresh opisuje wynik obu requestów.
3. Cross-origin login/refresh/logout i request bez CSRF są odrzucone; cookie działa w obu jawnych profilach i nie pojawia się w JSON/logach.
4. Payload XSS w raw_event, notatce, IOC i regule pozostaje tekstem. Query/YAML nie umożliwia SQL, odczytu plików, wywołania sieci ani wykonania kodu.
5. Test bezpośrednim SQL jako runtime dowodzi braku UPDATE/DELETE/TRUNCATE audytu. Zasymulowany błąd audytu wycofuje zmianę incydentu.
6. Limity body, parsera, czasu query i współbieżności działają pod obciążeniem. Przyjęte eventy przetrwają restart oraz niedostępność Redis/ClickHouse.
7. Wszystkie infrastrukturalne kroki SOAR zapisują wyłącznie wynik simulation. Test środowiskowy potwierdza brak próby połączenia do adresu z IOC.

Dowody testów będą dołączane w fazach implementacyjnych. Ten dokument nie zastępuje niezależnego przeglądu bezpieczeństwa przed rzeczywistym wdrożeniem.
