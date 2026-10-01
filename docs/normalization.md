# Normalizacja zdarzeń — kontrakt adapterów v1

Ten dokument opisuje zaimplementowane parsery PHASE 3. Wynik parsera ma
`schema_version: "1.0"` i `parser_version: "1.0.0"`. Nie oznacza to ukończenia
całej fazy ani zgodności ze wszystkimi formatami produktów. Wyniki integracji
pipeline i wyszukiwania są rejestrowane osobno w raporcie walidacji.

## Wejście i zaufane pola

Ingestion przyjmuje envelope z `source_type`, `raw_event` oraz opcjonalnymi
`source_event_id`, `timestamp` i `timezone`. Nadal obowiązują limity przyjęcia:
64 KiB UTF-8 na raw event, 1 MiB body, 500 pozycji batcha i 16 poziomów JSON.
Obiekt JSON zachowuje treść danych; tekst zachowuje oryginalną postać.

Normalizator otrzymuje z PostgreSQL zaufany kontekst: `event_id`, `source_id`,
`dataset_id`, `run_id`, `mode`, nazwę i typ źródła, konfigurację strefy,
`received_at`, `processed_at` i `raw_sha256`. Pola raw o tych nazwach ani
`source.name/type` nie zmieniają scope. Generic JSON oznacza takie próby flagą
`scope_fields_ignored`. `raw_sha256` jest SHA-256 kanonicznego envelope
przyjętego przez ingestion, opisanym w [modelu danych](data-model.md).
Normalizator zachowuje raw wraz z tą sumą; nie oblicza hasha innej reprezentacji.

Pola `risk`, `role`, rule ID i MITRE nie są faktami wyprowadzanymi z logu.
Nie powstają też wymyślone process GUID, host ID ani identyfikatory sesji.
Wynik jest zagnieżdżonym `NormalizedSecurityEvent`, opisanym w modelu danych;
nieobecne fakty mają `null`.

## Czas i pochodzenie

Kolejność wyboru czasu zdarzenia jest następująca:

1. Jawny RFC3339 z offsetem w `envelope.timestamp`.
2. RFC3339 w raw JSON: `timestamp`, `@timestamp`, `event_time`, `TimeCreated`
   lub `System.TimeCreated.SystemTime`.
3. Czas rozpoznany przez format: prefix Linux syslog, nginx CLF albo Sysmon
   `EventData.UtcTime`.
4. Serwerowy czas obserwacji `received_at`, z obiema flagami
   `timestamp_from_received_at` i `missing_source_timestamp`.

Wartość z punktu 4 nie jest deklaracją czasu zdarzenia po stronie źródła.
Reguły czasowe muszą uwzględniać jej pochodzenie. Błędny jawny czas raw albo
niepoprawny czas rozpoznawanego formatu trafia do kwarantanny; wyższy priorytet
envelope nie ukrywa takiego błędu. Nie stosujemy cichego fallbacku dla
niepoprawnej daty.

Wszystkie czasy wyniku są UTC. Zakres przechowywania to
`1970-01-01T00:00:00Z ≤ czas < 2300-01-01T00:00:00Z`; sprawdzenie następuje po
przeliczeniu offsetu. Rozdzielczość wyniku to mikrosekundy; dokładniejsza
frakcja RFC3339 nie zachowuje nanosekund. Nazwy miesięcy adapterów są jawnie
angielskie i nie zależą od języka systemu operacyjnego.

Syslog bez roku używa skonfigurowanej strefy IANA źródła i najbliższej poprawnej
daty w roku `received_at ± 1`, mierzonej względem lokalnego czasu obserwacji.
Flaga `inferred_year` oznacza wybrany czas syslog; znika, gdy wybrano dokładny
czas envelope/raw. Najbliższa data przypadająca w luce lub powtórzeniu DST
jest błędem `nonexistent_local_time` albo `ambiguous_local_time`. Remis lat
również wymaga kwarantanny. Dla archiwalnych logów collector powinien podać
dokładny `timestamp`; syslog bez roku nie może odtworzyć dowolnie starej daty.
Opcjonalne `envelope.timezone` pozostaje w raw, ale nie zastępuje zaufanej
konfiguracji strefy źródła.

## Generic JSON

`generic_json` akceptuje JSON object albo tekst zawierający JSON object.
Tekst JSON nie może zawierać powtórzonych kluczy, NaN, Infinity ani zbyt
głębokiego obiektu. Lista albo prymityw nie są eventem generic.

Obsługiwane grupy i pola:

| Grupa | Pola wejściowe |
| --- | --- |
| `source`, `destination` | `ip`, `port` |
| `host` | `id`, `name`, `os` |
| `user` | `id`, `name`, `realm`, `target` z `id/name/realm` |
| `session` | `id`, `provider`, `host_id`, `boot_id` |
| `process` | `entity_id`, `parent_entity_id`, `name`, `executable`, `command_line`, `pid`, `parent_pid`, `hash` |
| `event` | `category`, `type`, `action`, `outcome`, `severity`, `code` |
| `network` | `protocol`, `transport`, `bytes`, `packets` |
| `http` | `request_method`, `url`, `status_code`, `version`, `user_agent`, `referrer`, `bytes` |
| `file` | `name`, `path`, `hash` |

Aliasy wejściowe: `username → user.name`, `hostname → host.name`,
`source_ip/port → source.ip/port`, `destination_ip/port → destination.ip/port`,
`process_name → process.name`, `command_line → process.command_line`,
`action → event.action`, `severity → event.severity`, `result → event.outcome`.
`result: "failed"` mapuje na `failure`, a `"succeeded"` na `success`.
Sprzeczny alias i pole zagnieżdżone dają `conflicting_event_fields`.

Nieznane pola pozostają w raw i powodują `unmapped_fields`; nie są przenoszone
do typowanego wyniku. `message` pozostaje raw bez deklaracji rozpoznanej akcji.
Brak `event` daje `category/type/action: "unknown"`, `outcome: "unknown"`
i `severity: "informational"`.

## Linux auth

`linux_auth` akceptuje tekst lub JSON z polem `message` zawierającym pełną
linię. Prefix to RFC3164 `Mmm dd HH:mm:ss host program[pid]: message` albo
`RFC3339 host program[pid]: message`, z opcjonalnym `<PRI>`. PID jest opcjonalny.
Nie jest to pełny parser RFC5424 z structured data.

| Treść | Wynik |
| --- | --- |
| `sshd` / `sshd-session`: `Accepted` lub `Failed METHOD for [invalid user] USER from IP port PORT ssh2` | `authentication`, `ssh_login`, success/failure; metoda i invalid user w extensions; dopuszczony suffix klucza po `ssh2:` |
| `sudo`: `ACTOR : [DETAILS ;] TTY=... ; PWD=... ; USER=TARGET ; COMMAND=...` | Actor i target oddzielnie, pole command line, `sudo_command`; jawne denied/incorrect password/authentication failure dają failure |
| `su`: `session opened/closed for user TARGET [(uid=...)] [by ACTOR(uid=...)]`, opcjonalny prefix PAM | `su_session`, start/end; brak actor pozostaje null |
| `su`: `FAILED SU (to TARGET) ACTOR on TTY` | `su_session`, failure |

Sudo i su nie otrzymują automatycznie wysokiej severity ani etykiety exploit.
SSH failure ma `low`, success `informational`. Inne wiadomości sshd,
np. `Partial` lub `Postponed`, oraz nieznane programy trafiają do kwarantanny
`unsupported_linux_auth`; nie są zgadywanym sukcesem ani błędem logowania.
Semantykę prefixu opisuje [RFC3164](https://www.rfc-editor.org/rfc/rfc3164),
a postać wyniku uwierzytelniania potwierdza
[kod OpenSSH](https://raw.githubusercontent.com/openssh/openssh-portable/master/auth.c).

## Windows JSON

`windows_auth` i `windows_process` obsługują JSON object lub jego tekstową
reprezentację. Collector dostarcza `EventID` na górze lub w `System`, `Computer`
na górze lub w `System`, a nazwane pola jako mapę `EventData` / `event_data`.
Płaski obiekt z polami eventu również jest obsługiwany. `EventID` może być liczbą,
tekstem cyfr albo `System.EventID.Value`. XML, EVTX i lista XML `Data` wymagają
konwersji w collectorze.

| Event | Semantyka |
| --- | --- |
| [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) / [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) | `Subject*` to actor w `user`; konto udanego/nieudanego logowania z `Target*` znajduje się w `user.target`. `IpAddress/IpPort` to source. Wyłącznie 4624 zapisuje `TargetLogonId` jako session ID z provider `windows_security`. |
| [4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) | Actor `Subject*`; utworzone konto `TargetSid/TargetUserName/TargetDomainName` w `user.target`; `user_created`. |
| [4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732) | Actor `Subject*`; dodane konto z `MemberSid` w `user.target.id`. `TargetSid/TargetUserName/TargetDomainName` opisują grupę w `extensions.group`, nie konto. `MemberName` pozostaje distinguished name w extensions. |
| [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) | Actor procesu `Subject*`, opcjonalny wykonawca `Target*`; executable `NewProcessName`, PID `NewProcessId`, parent PID `ProcessId`, opcjonalna `CommandLine`. PID w postaci hex jest konwertowany na liczbę. `System.Execution.ProcessID` nie staje się PID-em nowego procesu. |
| [Sysmon 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Wymagany provider `Microsoft-Windows-Sysmon`; `Image`, `CommandLine`, `ProcessId`, `ParentProcessId`, `ProcessGuid`, `ParentProcessGuid`, `Hashes`. `User` rozdziela jawny `REALM\\ACCOUNT`. `UtcTime` z eksportu jest UTC; provider zostaje w extensions. |

Wyszukiwanie kont atakowanych w 4624/4625 musi używać `user.target.name/id`,
a nie przypisywać prób logowania do raportującego SYSTEM. Korelacja
4720 → 4732 może użyć target SID. Administratorzy mogą mieć lokalizowane nazwy
grup; parser zachowuje SID i nie wyprowadza privilege z nazwy konta/grupy.
Puste wartości, `-` i NULL SID `S-1-0-0` są null; port 0 pozostaje poprawną
wartością, jeśli źródło go podało. Nazwa hosta nie jest kopiowana do host ID.
Brak command line nie powoduje utworzenia pustego polecenia. Pozostałe Windows
event IDs są `unsupported_windows_event`.

## Firewall i nginx

`firewall` jest określonym adapterem key=value, a nie obietnicą obsługi każdego
vendora. Przyjmuje tekst z tokenami rozdzielonymi spacjami (wartości mogą być
w cudzysłowach) albo obiekt JSON. Powtórzone klucze w tekście są błędem.
Wymagane `action`: `allow`, `accept`, `deny`, `drop` lub `reject`.
Pozostałe pola: `timestamp` RFC3339, `hostname`, `src` / `source_ip`,
`dst` / `destination_ip`, `spt` / `source_port`, `dpt` / `destination_port`,
`proto` / `protocol`, `bytes`, `packets`. Protocol jest transportem lowercase.
Allow/accept to success, pozostałe failure; category to network, a severity
informational. Nieznane nazwy pól nie stają się rozpoznanym faktem.

`nginx` obsługuje standardowy combined:

```text
REMOTE_ADDR - REMOTE_USER [DD/Mon/YYYY:HH:MM:SS +HHMM] "METHOD TARGET HTTP/VERSION" STATUS BODY_BYTES "REFERER" "USER_AGENT"
```

JSON używa `remote_addr`, `remote_user`, `request`, `status`,
`body_bytes_sent`, `http_referer`, `http_user_agent`, `time_local`; RFC3339 raw
może podać dokładniejszy czas. Wymagany jest status HTTP 100–599.
Znacznik `-` oznacza brak wartości. Combined dekoduje domyślne nginx `\xXX`
jako bajty UTF-8, również escaped quotes; błędne escapowanie nie jest
akceptowane. Bytes opisuje body bytes sent, a nie cały ruch sieciowy.
Semantykę i escaping opisuje
[oficjalny moduł logowania nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html).

HTTP 4xx/5xx ma outcome failure dla żądania web. Nie jest automatycznie
authentication failure ani dowodem ataku; category pozostaje web,
action `http_request`, severity informational. Custom log_format wymaga
mapy JSON z podanymi polami lub nowego wersjonowanego adaptera.

## Typy, granice i błędy

IP muszą być adresami IPv4/IPv6, nie liczbami ani hostname. Wspólna
kanonikalizacja dla parsera i query zapisuje IPv4-mapped IPv6 w postaci
hex, np. `::ffff:c000:205`; wejście `::ffff:192.0.2.5` wskazuje ten sam adres.
Porty są 0–65535, PID 0–4294967295. Liczby pól generic są typowane ściśle;
tekst `"22"` nie staje się portem, podczas gdy tekstowe adaptery logów
konwertują udokumentowane cyfry. `event.outcome` to success/failure/unknown;
severity to informational/low/medium/high/critical.

Typowy krótki tekst ma limit 256 znaków, ścieżki 1024, command line i URL 8192.
NUL jest zabroniony. `extensions` to JSON object: maksymalnie 64 pola na
górze, 8192 bajty kanonicznego UTF-8, sześć poziomów kontenerów, 128 znaków
klucza i 128 elementów listy. Nie jest wykonywanym kodem ani szablonem.
Quality ma wyłącznie stałe flagi, bez tekstu źródłowego, maksymalnie 16 pozycji;
powtórzenia są usuwane.

Błędna zawartość po przyjęciu do trwałego inbox daje bezpieczny reason code,
np. `invalid_timestamp`, `invalid_event_fields`, `invalid_json`,
`unsupported_linux_auth` czy `unsupported_windows_event`. Exception nie
zawiera raw ani sekretów. Kwestionowany raw pozostaje dostępny w trwałym
magazynie i statusie pipeline; sama normalizacja nie usuwa ani nie przepisuje
historii. Reguły retry i projekcji opisuje dokument operacyjny PHASE 3.

## Dowód parserów

Fixture wejścia/oczekiwanych faktów znajduje się w
`backend/tests/fixtures/normalization/golden.json`; unit tests w
`backend/tests/unit/test_normalization.py`. Obejmują wszystkie sześć adapterów,
actor/target/SID, Unicode, IPv6, null, priorytet i granice czasu, zmianę roku,
DST, spoofing scope, konflikty aliasów, JSON injection shapes oraz limity.
Nie są dowodem przejścia API → PostgreSQL → ClickHouse; taką bramkę wykonuje
osobny zestaw integracyjny i raport walidacji.
