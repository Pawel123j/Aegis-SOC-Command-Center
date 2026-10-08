# Mini SOAR — Etap 10

Stan implementacji: 2026-10-08. Ręcznie uruchamiane, wersjonowane procedury
reagowania z trwałą historią w PostgreSQL. [Wyniki odbioru](validation-soar.md),
[decyzja architektoniczna](adr/0016-durable-local-playbooks.md).

## Praca w panelu

1. Kierownik SOC lub administrator otwiera **Procedury SOAR → Nowa procedura**.
   Wybiera uporządkowane kroki, zapisuje wersję roboczą i osobno ją publikuje.
2. W szczegółach alertu operator otwiera **Procedury SOAR dla alertu**,
   wybiera opublikowaną wersję, źródłowe zdarzenie i stronę adresu IP.
3. Panel pokazuje plan i lokalne skutki. Po potwierdzeniu planu operator
   wybiera **Uruchom w trybie SIMULATION**.
4. Szczegóły pokazują stan każdego kroku, czas, próby, wyniki i dowody.
   Historia oraz prywatna skrzynka powiadomień są dostępne w module SOAR.

Każdy run ma `execution_mode=simulation`. Oddzielne `mode=live/replay` oznacza
pochodzenie danych. Symulacja infrastruktury może tworzyć rzeczywiste
**lokalne** incydenty i powiadomienia; panel informuje o tym przed startem.
Nie ma adaptera, ustawienia ani endpointu włączającego prawdziwą blokadę.
Domyślny szkic zawiera sześć kroków analizy podejrzanego IP. Pusta instalacja
nie otrzymuje automatycznie opublikowanych procedur ani wygenerowanych alertów.

## Zamknięty rejestr akcji

| Akcja | Rzeczywiste zachowanie |
| --- | --- |
| `enrich_ip` | Lokalna walidacja i wersja adresu pochodzącego z dowodu; bez DNS/HTTP |
| `check_threat_intelligence` | Przypięty wynik pierwszej analizy wybranego zdarzenia, zawężony do wybranego IP; brak analizy pozostaje `pending` |
| `calculate_risk` | Zachowana ocena alertu, polityka i wyjaśnienie; bez dowolnego podnoszenia punktów; brak oceny jest jawny |
| `create_incident` | Istniejąca otwarta sprawa lub utworzenie przez wspólną usługę incydentów; brak duplikatu przy ponowieniu |
| `add_ioc` | W live nowy **nieaktywny** IP o nieznanej reputacji do przeglądu; istniejący wpis bez zmian; w replay tylko symulacja |
| `notify_analyst` | Powiadomienie w prywatnej skrzynce inicjatora; bez email, Slack i innych odbiorców |
| `simulate_block_ip` | Utrwalony plan blokady IP, bez połączenia z celem |
| `simulate_isolate_host` | Utrwalony plan izolacji hosta, bez działania na urządzeniu |
| `simulate_webhook` | Utrwalony plan; definicja nie przyjmuje adresu webhooka |

Brak IP/hosta daje jawne `not_applicable`. Zamknięty lub rozwiązany incydent
wymaga decyzji operatora; procedura nie otwiera go i nie tworzy zamiennika.
Reputacja IOC jest deklaracją źródła, a score nie potwierdza ataku.

## Definicja i dowód

Definicja to ściśle walidowany JSON, nie wykonywalny YAML lub skrypt.
`schema_version` jest liczbą całkowitą 1. Dopuszczamy nazwę do 128 znaków,
opis do 1024 i 1–20 kroków z unikalnym `id` oraz jedną dozwoloną akcją.
Nie przyjmujemy parametrów akcji, kodu, URL, ścieżek, wyrażeń, interpolacji
ani nieznanych pól. Powtórzone klucze JSON są odrzucane.

Opublikowany dokument, jego hash i wersja silnika są niezmienne. Edycja tworzy
nową rewizję i nie zmienia rozpoczętych wykonań. Start przyjmuje UUID alertu
i opcjonalnego zdarzenia będącego jego dowodem, nigdy dowolny tekst adresu.
Kontekst przypina zweryfikowany oryginał, jego hash, zakres danych, wynik TI
i wyjaśnienie ryzyka. Limit kontekstu to 24 KiB; większy dowód jest odrzucany,
bez cichego obcinania. Kanoniczny output akcji ma limit 32 KiB przed zapisem;
dodatkowy limit bazy wynosi 64 KiB. Nie zapisujemy sekretów połączeń.

## Trwałość, retry i anulowanie

Osobny proces `python -m app.soar` pobiera gotowe kroki z PostgreSQL.
Ten zakres używa trwałej kolejki w bazie, zgodnie z ADR 0016; nie ma drugiego
transportu Celery/outbox dla SOAR. Proces nie potrzebuje publicznej sieci.

1. API zatwierdza run, kroki `waiting`, kontekst i audyt w jednej transakcji.
   Wymagany `Idempotency-Key` chroni start tego samego operatora; ten sam
   request zwraca istniejący run, zmieniony request daje 409.
2. Proces przejmuje jeden gotowy krok, zapisuje `running`, numer próby oraz
   30-sekundową dzierżawę. Osobna transakcja wykonania ponownie sprawdza
   konto, rolę, wymagane permissions, procedurę, alert, deadline i dzierżawę.
3. Lokalny efekt, unikalny ledger kroku, wynik próby, audyt i gotowość kolejnego
   kroku zatwierdzane są razem. Końcowe sprawdzenie czasu następuje po flush.
4. Przerwanie przed commitem cofa efekty. Przerwanie po commicie nie powtarza
   ukończonego kroku. Wygasła dzierżawa jest odzyskiwana z kolejnym numerem
   próby; poprzedni wykonawca nie może zatwierdzić wyniku.

Maksymalnie trzy próby na krok; po błędzie chwilowym oczekiwanie 5 i 20 s.
Błędna definicja, utrata uprawnień, uszkodzony dowód i nieprawidłowy target
nie podlegają retry. Deadline całego wykonania to 10 minut. Limit katalogu
wynosi 100 procedur, 20 rewizji na procedurę oraz 100 aktywnych wykonań.

Stany run: `queued`, `running`, `completed`, `failed`, `cancelled`.
Stany kroku: `waiting`, `running`, `completed`, `failed`. Anulowanie
serializuje się z zatwierdzeniem efektu; wcześniejsze efekty pozostają.
Nierozpoczęte kroki mają `not_executed_reason`, widoczny jako niewykonanie.
Historia terminalna, próby i efekty są chronione również w bazie.

Ponowienie nieudanego/anulowanego przebiegu tworzy **nowy** run z `replay_of`,
tym samym alertem, rewizją, zdarzeniem i stroną IP. Wersja musi nadal być
opublikowana. Panel ponownie pokazuje plan. Nowe lokalne powiadomienie jest
jawnym skutkiem ponowienia, natomiast incydent zachowuje deduplikację.

## Uprawnienia i granice

Odczyt wymaga łącznie `playbooks:read`, `events:read`, `alerts:read`,
`incidents:read`, `intelligence:read`; wykonanie dodatkowo `playbooks:run`.
Tworzenie incydentu wymaga `incidents:edit`, a dodanie IOC
`intelligence:manage`. Zarządzanie i publikacja wymagają `playbooks:manage`.
Anulować może inicjator z prawem uruchamiania lub zarządzający procedurami.
Zmiany konta i uruchomienia stosują wspólną blokadę autoryzacji przed
blokadami wierszy. UI odświeża uprawnienia przed mutacją i usuwa dane przy
zmianie sesji; serwer pozostaje źródłem decyzji dostępu.

Odczyty mają limit 120/min, mutacje 30/min na operatora. Lista wykonań
domyślnie obejmuje live; replay wymaga dokładnych `dataset_id` i niezerowego
`data_run_id`. Limit strony to 50, kursor jest związany z zakresem. Skrzynka
pokazuje wyłącznie powiadomienia odbiorcy. Odczyty mają `Cache-Control: no-store`.

Nie ma automatycznych triggerów, pętli/warunków, zewnętrznych providerów,
arbitralnej zmiany ryzyka ani rzeczywistych działań infrastrukturalnych.
Awaria PostgreSQL zatrzymuje pracę bez utraty zatwierdzonej historii.
Kontrola integralności/granty nie chronią przed właścicielem bazy, który
świadomie wyłączy zabezpieczenia. Migracja `0012_soar` blokuje downgrade,
jeżeli istnieją procedury, aby nie usuwać historii.

Testy i wyniki: [raport Etapu 10](validation-soar.md). Kolejny etap:
Dashboard — zbiorczy widok rzeczywistych danych SOC.
