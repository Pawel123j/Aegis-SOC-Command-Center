# Threat Hunting i bezpieczny język zapytań

Status: **projekt PHASE 0, bez implementacji**. Hunt służy do sprawdzania hipotezy na zdarzeniach, zapisywania odtwarzalnego zapytania i przekazania wyniku do investigation lub draftu detekcji.

## Przepływ pracy

Analityk zapisuje hipotezę, wybiera przedział czasu UTC i filtry, wykonuje ograniczone zapytanie, oznacza wyniki i utrwala wybrane eventy jako evidence. Wynik pozytywny może utworzyć investigation. Uogólnienie zachowania tworzy **nieaktywny draft** reguły z fixture pozytywną i negatywną; do jej publikacji potrzebne są walidacja i uprawnienia Manager/Admin. Jeden interesujący event nie staje się automatycznie regułą produkcyjną ani incydentem.

Każde wykonanie wskazuje `dataset_id`; domyślnie live. Replay demo jest oddzielną przestrzenią o skończonym wejściu i przypiętych wersjach. UI pokazuje tryb i dataset, a API dołącza scope jako obowiązkowy predykat spoza AST użytkownika. Hunt ani zmieniony cursor nie może połączyć danych różnych scenariuszy lub przekroczyć uprawnień do datasetu.

| Obiekt PostgreSQL | Co zachowuje |
| --- | --- |
| Saved hunt | UUID, title, hypothesis, owner, visibility, tekst query, AST/schema version, revision, created/updated |
| Hunt run | Hunt revision lub query ad hoc, absolutny zakres czasu, snapshot cutoff ingestion, wykonawca, limity, status, liczba wyników, query hash |
| Bookmark | Hunt/run ID, event ID, notatka, autor, czas; unikalność `(run_id, event_id, actor_id)` |
| Evidence | Niezmienny snapshot wybranego eventu, provenance i hash, zgodny z incident-response |
| Draft detection | Query/AST source, autor, hypothesis, rule type, metadane, test fixtures, `enabled=false` |

Saved hunt może być prywatny albo dostępny organizacji. Autor może edytować własny zapis; Manager/Admin zarządza współdzielonym katalogiem. Odczyt prywatnego hunt wymaga własności albo Manager/Admin. Samo wspólne prawo do logów nie ujawnia prywatnych notatek. Read Only może uruchomić zapytanie ad hoc i odczytać udostępniony katalog, ale nie zapisuje hunt, bookmarków ani investigation.

## Query language v1

Proponowany język to niewielki DSL, nie SQL i nie wykonywalny Python. Query builder i edytor tekstowy kompilują się do tego samego typowanego AST. Pola po kropce oznaczają publiczne nazwy schematu; adapter mapuje je na stałe fizyczne kolumny, np. `source.ip` → `source_ip`.

```text
expression := or_expression
or_expression := and_expression ("OR" and_expression)*
and_expression := unary_expression ("AND" unary_expression)*
unary_expression := "NOT" unary_expression | "(" expression ")" | predicate
predicate := field comparison literal
           | field "IN" "[" literal ("," literal)* "]"
           | field "CONTAINS" string
           | field "EXISTS"
comparison := "=" | "!=" | ">" | ">=" | "<" | "<="
```

Precedencja: nawiasy, `NOT`, `AND`, `OR`. Keywords uppercase, identyfikatory case-sensitive z allowlist. Literały tekstowe używają cudzysłowów i escaping zgodnego z JSON; liczby są skończone. `CONTAINS` oznacza literalny, case-sensitive substring bez regex/glob. Operatory porządku są dostępne tylko dla liczb/czasu, IP porównujemy po kanonizacji do typu adresu. `IN` wymaga jednego typu elementów. Dla nullable pola każde porównanie, w tym `!=`, daje false przy braku wartości; `EXISTS` sprawdza obecność. Następnie `NOT` neguje ten wynik, więc `NOT field = "x"` obejmuje także brak pola; UI ma to objaśniać.

Dozwolone pola obejmują `timestamp`, `event_id`, `event.category`, `event.type`, `event.action`, `event.outcome`, `event.severity`, `source_id`, `source.type`, `source.ip`, `source.port`, `destination.ip`, `destination.port`, `host.name`, `user.name`, `process.name`, `process.command_line` oraz zarejestrowane pola filtrów enrichment. Schemat normalizacji definiuje typy. Przyjazny alias `result` mapuje się na `event.outcome`; wartość wejściowa `failed` mapuje się na kanoniczne `failure`. Alias `severity` oznacza `event.severity`, nie severity alertu. Backend i UI pokazują wersję skompilowanego zapytania, aby alias nie tworzył innej semantyki.

`alert.severity`, `mitre.technique.id` i `detection.rule.id` są filtrami wyników detekcji, a nie dowolnymi etykietami nadanymi przez nadawcę logu. Plan query używa ograniczonej projekcji powiązań alert-event w ClickHouse. Projekcja ma wersję/watermark; wynik pokazuje jej opóźnienie. Nie wolno generować nieograniczonego `IN` z identyfikatorów odczytanych z PostgreSQL. Jeżeli projekcja nie jest dostępna, API zgłasza ograniczenie, zamiast bezgłośnie pomijać filtr.

## Bezpieczeństwo i limity

Parser zwraca AST; walidator sprawdza pola, typy i koszt; compiler tworzy statyczny szablon SQL z parametrami. Żaden fragment query użytkownika nie jest wklejany do SQL, nazwy tabeli, `ORDER BY`, `SETTINGS` ani funkcji. Użytkownik nie podaje nazw baz ani funkcji tabelowych; `url()`, `file()`, remote queries, SQL komentarze i wiele statements nie należą do gramatyki. Parametry ClickHouse mają jawne typy, zgodnie z [dokumentacją składni](https://clickhouse.com/docs/sql-reference/syntax#defining-and-using-query-parameters).

| Limit projektowy | Wartość początkowa |
| --- | --- |
| Długość query | 8 KiB |
| Głębokość AST / liczba predicate | 10 / 50 |
| Długość literału / elementy `IN` | 512 znaków / 100 |
| Zakres czasu | Domyślnie 24 h, maksymalnie 7 dni interaktywnie, obowiązkowy; większy zakres jako kontrolowany job |
| Wyniki | 100/stronę, maksymalnie 500/stronę i 10 000/run |
| Równoległość | 2 query/użytkownika, wspólny limit globalny dopasowany do hosta |
| Wykonanie w ClickHouse | 5 s, 1 mln czytanych wierszy, 256 MiB pamięci per query |
| Deadline API | 8 s wraz z anulowaniem zapytania serwera |

Limity są konfiguracją serwera i profilem użytkownika ClickHouse tylko do odczytu, a nie parametrami, które operator może wyłączyć. Przekroczenie kosztu daje jawny błąd `query_limit_exceeded`, nigdy pozornie kompletny pusty wynik. ClickHouse ma limity czasu, odczytów i pamięci, ale ich egzekwowanie zależy od etapów przetwarzania; testy na przypiętej wersji muszą potwierdzić działanie profilu. Zob. [Restrictions on query complexity](https://clickhouse.com/docs/operations/settings/query-complexity). Wartości nie są deklaracją osiągniętej wydajności.

Paginacja jest kluczowa `(timestamp, event_id)` z ustalonym kierunkiem, bez rosnącego OFFSET. Cursor jest podpisany i powiązany z query hash, użytkownikiem, zakresem czasu, cutoff ingestion oraz wersją schema/projekcji. Zmiana filtra unieważnia cursor. Odpowiedź zawiera `has_more`, `truncated`, `projection_watermark`, `query_id` i efektywne limity. Cutoff eliminuje część zmian wyników przez nowe eventy, ale nie gwarantuje transakcyjnego snapshotu między dwiema bazami; opóźniona projekcja może zmienić kolejne wykonanie. Odtwarzalny dowód wymaga utrwalenia wybranych snapshotów, nie tylko zapamiętania tekstu query.

## Przykładowe hipotezy

Przykłady są kontraktem przyszłego języka; nie są obecnie wykonywalnymi poleceniami.

| Hipoteza | Query v1 | Interpretacja |
| --- | --- | --- |
| Źródło próbuje logować się na wiele kont | `source.ip = "192.0.2.10" AND event.category = "authentication" AND event.outcome = "failure"` | Obejrzyj użytkowników i oś czasu; samo wyszukanie nie realizuje threshold |
| Konto zalogowało się po serii błędów | `user.name = "demo.alice" AND event.category = "authentication"` | Investigation zestawia failure/success; kolejność i okno wymagają reguły sequence |
| Podejrzany parametr PowerShell | `process.name = "powershell.exe" AND process.command_line CONTAINS "-EncodedCommand"` | Wymaga kontekstu i uwzględnienia innych wariantów wielkości liter/argumentów w detekcji |
| Zmiany administracyjne na hoście | `host.name = "demo-windows-01" AND event.action IN ["user_created", "user_added_to_admin_group"]` | Zweryfikuj wspólną tożsamość konta i uprawnienia wykonawcy |
| Aktywność znanego IOC | `source.ip = "198.51.100.23" OR destination.ip = "198.51.100.23"` | Adres dokumentacyjny w demo; reputacja pochodzi z lokalnego fixture TI |
| Niezwykłe sudo | `process.name = "sudo" AND user.name != "demo.automation"` | Hipoteza do zbadania; nie stanowi dowodu exploitacji |

## API i promocja do detekcji

Planowane kontrakty: `POST /api/v1/events/search` dla ad hoc, `GET/POST /api/v1/hunts`, `PATCH /api/v1/hunts/{id}`, `POST /api/v1/hunts/{id}/runs`, `POST /api/v1/hunts/{id}/bookmarks`, `POST /api/v1/hunts/{id}/investigations`, `POST /api/v1/hunts/{id}/draft-detections`. Operacje trwałe mają audit, kontrolę wersji i idempotency key. Payload run zawiera `from`, `to`, query/version i limit; daty względne są rozwiązywane do UTC raz, na początku wykonania.

Draft detekcji zachowuje origin hunt/run, AST, wybrane eventy testowe, opis „dlaczego to może być istotne”, sugerowaną severity/confidence i false-positive guidance. Translator obsługuje tylko zgodny podzbiór pól/operatorów detection engine; nieobsługiwany element daje czytelny błąd. Nie próbujemy automatycznie zamienić sequence albo korelacji w pojedynczy filtr. Publikacja wymaga jawnego rule type, okna/klucza grupowania, metadanych ATT&CK i testów pozytywnych/negatywnych opisanych w [detection-engine.md](detection-engine.md).

## Kryteria odbioru

1. Testy AST obejmują precedencję, nawiasy, aliasy, nullable, escaping, IPv4/IPv6, typy oraz odrzucanie nieznanych pól.
2. Payload ze SQL, funkcją sieciową, komentarzem, nieznanym sortowaniem lub bardzo głębokim AST nie trafia do wykonania.
3. Test integration potwierdza parametryzację i limits na rzeczywistym ClickHouse, anulowanie po timeout i brak niejawnych wyników częściowych.
4. Paginacja stabilnie rozstrzyga równy timestamp przez event ID; cursor z innego query/użytkownika jest odrzucony.
5. Snapshot evidence jest dostępny po retencji źródła; run zachowuje zakres absolutny, query i wersje wymagane do interpretacji.
6. Analyst tworzy draft `enabled=false`; Read Only nie zapisuje hunt, a nieuprawniona aktywacja draftu zwraca 403.
7. Opóźniona projekcja alert-event jest widoczna jako watermark/lag; filtr MITRE/rule nie jest ignorowany.
