# UEBA — obserwowana aktywność użytkowników i hostów

Etap 9 dodaje porównanie zakończonej doby UTC z 28 wcześniejszymi dobami.
W profilu użytkownika lub hosta wybierz dzień i uruchom analizę. Widok pokazuje
wartość obserwowaną, historię porównania, punktację, uzasadnienie i oryginalne
zdarzenia. Polityka ma wersję `ueba-statistics-v1`.

## Zakres API

`GET /api/v1/entities/{entity_id}/ueba?day=2026-10-05&mode=live`.
Bez `day` analizowana jest poprzednia doba UTC. Bieżąca i przyszłe doby są
odrzucane. Replay wymaga `mode=replay`, `dataset_id` oraz niezerowego `run_id`.
Tożsamość profilu musi należeć do tego zakresu. Wymagane są łącznie permissions
`events:read`, `alerts:read`, `incidents:read`. Odpowiedź ma `no-store`.

Raport zawiera scope, wersję polityki, okna observation/baseline, liczniki
zdarzeń i odrzuconych czasów oraz siedem wskaźników. Każdy wskaźnik ma status,
score, explanation, wartości baseline/observed i ograniczoną listę dowodów.
Dowód zachowuje UUID, dokładny timestamp oraz hash dokumentu; otwiera istniejący
widok oryginalnego zdarzenia. Łączny score jest maksimum wskaźników, odrębnym
od istniejącej oceny ryzyka alertów i incydentów.

`GET /api/v1/entities/{entity_id}/ueba/events/{event_id}` wymaga tych samych
parametrów dnia i zakresu oraz `document_sha256`. Ponownie wylicza raport
w jednej migawce PostgreSQL i zwraca zweryfikowany oryginał tylko wtedy,
gdy UUID i hash nadal należą do jego udostępnionych dowodów. Brak dopasowania
daje `409 ueba_changed` i wymaga odświeżenia analizy. Otwarcie nie zależy od
projekcji ClickHouse. Oba endpointy współdzielą limit 30 odczytów na minutę.

## Wskaźniki i ograniczenia danych

| Wskaźnik | Porównanie |
| --- | --- |
| Nietypowa godzina logowania | Udane logowanie w godzinie UTC nieobecnej w historii udanych logowań |
| Nowy adres logowania | Zaobserwowany source IP nieobecny w tej historii; adres może reprezentować NAT |
| Nowy host logowania | Nowy obserwowany host zdarzenia dla konta z pełnym SID w jednym źródle |
| Pierwsze narzędzie administracyjne | Nowa dokładna nazwa znanego narzędzia w zdarzeniach procesu; nazwa nie dowodzi zamiaru |
| Wzrost nieudanych logowań | Dobowa liczba względem średniej i odchylenia standardowego 28 dób |
| Wzrost aktywności | Dobowa liczba wszystkich kwalifikujących się zdarzeń względem 28 dób |
| Użycie konta administratora | Jawnie nieobsługiwane: schemat nie dostarcza potwierdzonego faktu uprawnień |

Logowanie na hoście Windows nie jest identyfikacją komputera klienta. Konta
oparte wyłącznie na nazwie lub lokalnym UID nie są łączone między hostami.
Role docelowe i role aktora są rozpatrywane zgodnie z treścią zdarzenia.

Logowania muszą mieć kategorię `authentication`, typ `start` i znany wynik.
Zamknięcie sesji nie jest nowym logowaniem. Proces musi mieć kategorię `process`,
typ `start`, obserwowaną nazwę/ścieżkę i nie może być oznaczony jako nieudany.
Dokładne nazwy narzędzi w tej wersji to: powershell.exe, pwsh.exe, cmd.exe,
wmic.exe, psexec.exe, sc.exe, schtasks.exe, reg.exe, net.exe, net1.exe, sudo,
su i systemctl. Ścieżka executable ma pierwszeństwo przed process.name;
reguły separatorów i wielkości liter Windows obowiązują tylko dla Windows.

Windows 4624/4625 zawsze przypisuje logowanie do roli target. Gdy nie można
rozpoznać konta docelowego, zdarzenie nadal liczy się dla hosta, lecz nie staje
się logowaniem konta Subject/SYSTEM. Ta sama zasada dotyczy celu sesji su
w logach Linux. Wzrost aktywności profilu zlicza powiązane
zdarzenia niezależnie od roli; nie jest liczbą własnych działań użytkownika.

Punktacje wykrytych odchyleń są stałymi wagami przeglądu: godzina 35, IP 40,
host 45, narzędzie 50, nieudane logowania 55, aktywność 30. Pozostały wynik
wskaźnika ma zero, ale brak dostatecznej historii całego profilu daje score
`null`, a nie zero. Próg wzrostu liczby zdarzeń to największa z wartości:
minimum 5 dla porażek lub 20 dla aktywności, średnia + 3 odchylenia standardowe
populacji, 3 × średnia. Dwa ostatnie składniki zaokrąglamy w górę. Wykrycie
następuje od progu włącznie. Statystyki obejmują wszystkie 28 dziennych koszyków.

## Historia, kompletność i bezpieczeństwo

Wspólne minimum baseline to 20 zdarzeń na 7 różnych dniach. Wskaźniki logowania
wymagają dodatkowo co najmniej 10 udanych logowań na 3 dniach, a narzędzia
co najmniej 10 zdarzeń procesu na 3 dniach. Brak historii daje `cold_start`
lub `insufficient_data`, bez anomalii. Niepełny indeks daje `index_pending`.
Profile IP i procesu mają `unsupported`.

Odczyt jest ograniczony do 2000 unikalnych powiązanych zdarzeń i 8 MiB dowodów,
30 żądań na minutę oraz 3 s czasu SQL. Przekroczenie pojemności lub uszkodzenie
dowodu zwraca 409. Odczyt nie próbuje ukrywać pominiętych zdarzeń przez sampling.
Obserwacje z zastąpionym lub niepewnym czasem źródła są liczone jako wykluczone.
Live i poszczególne replay mają osobne historie.

Integralność członkostwa opiera się na niezmiennym indeksie i grantach bazy.
Metadane receipts są sprawdzane dla okna danego źródła, a pełny raw/normalized
i zgodność wszystkich ról — dla powiązanych zdarzeń baseline i obserwacji.
Nie jest to dowód kompletności po celowym wyłączeniu triggerów przez właściciela
bazy i spójnym przepisaniu członkostwa indeksu. Brak receiptu w tym źródle
powoduje zachowawcze `index_pending`, nawet gdy zdarzenie może dotyczyć innego
profilu; bez indeksu nie można wiarygodnie rozstrzygnąć członkostwa.

Analiza nie zapisuje oceny w bazie. Późniejsze przyjęcie historycznego logu może
zmienić kolejne porównanie tego samego dnia. Zero wykrytych odchyleń oznacza
wyłącznie wynik tych wskaźników, a nie potwierdzenie bezpieczeństwa. Szczegóły
decyzji zawiera [ADR 0015](adr/0015-observed-behavior-baselines.md).
