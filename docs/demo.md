# Demo i scenariusz prezentacji

Status: projekt PHASE 0. Generator będzie implementowany w PHASE 14; fixtures
źródeł/reguł powstają wcześniej. Żaden opisany alert nie jest seedowany do bazy.

## Kontrakt generatora

Manifest run zawiera seed, scenario_version, dataset_id, run_id, mode=replay,
absolutny event-time range, listę raw source records, reguły i snapshoty wzbogacenia.
Generator uruchamia tę samą trasę `/api/v1/events` z credential ograniczonym do
datasetu. Po zamknięciu manifestu pipeline finalizuje skończony zbiór przez te same
parsery, normalizację, detection/correlation/risk i repozytoria co live. Publiczny
klient nie ustawia zegara serwera. Powtórzenie transportu nie zmienia liczby eventów.

Demo nie jest przyspieszonym live z pozmienianymi progami: używa jawnego trybu replay.
UI pokazuje nazwę datasetu, wersję i tryb; live metryki wykluczają te wyniki. Seed
tworzy konfigurację, reguły, asset inventory i lokalne IOC, nigdy gotowe alerty,
incydenty, wyniki testów czy playbook runs. Osobny smoke live sprawdzi prawdziwe
oczekiwanie na watermark. Zamknięte demo można powtórzyć bez czekania na czas śladu.

Normal activity zawiera poprawne auth, nginx, ruch firewall, zwykłe procesy i
zatwierdzone sudo. Rozkład jest jawny, deterministyczny i oznaczony jako syntetyczny.
Używamy lokalnych nazw oraz adresów z zakresów dokumentacyjnych; IOC to lokalne
fixture. Tryb offline oznacza brak zewnętrznych usług **w runtime**; pierwsze
pobranie obrazów i zależności nadal wymaga sieci albo wcześniej przygotowanego cache.

## Siedem scenariuszy

| ID | Raw zachowanie | Oczekiwany dowód po pipeline | Kontrola negatywna |
| --- | --- | --- | --- |
| 1 SSH brute force | 10+ nieudanych logowań jednej tożsamości/IP w 5 min | Threshold, evidence IDs i T1110, bez duplikatu od retry | 9 failures i event dokładnie na wyłącznym lewym brzegu |
| 2 Brute force → success | Failures, następnie success tej samej user/host/IP | Sekwencja i T1078; sygnały powiązane w case | Success innego user za tym samym NAT |
| 3 Suspicious PowerShell | Windows process z nazwą procesu i podejrzanym argumentem | Single-event z T1059.001 i pokazanym predykatem | Zwykły PowerShell bez podejrzanego argumentu |
| 4 Privilege escalation | Podejrzane użycie sudo/su lub adekwatny Windows privilege event | Właściwe mapowanie, np. T1548.003 dla nadużycia sudo | Zatwierdzone sudo; bez etykiety exploit T1068 bez dowodu |
| 5 Malicious IP IOC | Obserwowany IP pasuje do aktywnego IOC | IOC ID/version i wkład I do risk | IP niepasujące albo wygasły IOC |
| 6 Account compromise | Failures → success → process → privilege w powiązanej session | Jeden case z silnymi powiązaniami, chain i policzonym risk | Wspólny IP bez wspólnej tożsamości/session nie skleja spraw |
| 7 New administrator | Create account → add target SID do admin group | Sekwencja po target identity, mapping account/group | Ta sama nazwa, inny SID lub add poza 30 min |

Scenariusz 6 wymaga wiarygodnych session/process/host identity w wygenerowanych
logach; nie dopisujemy brakujących powiązań w backendzie tylko po to, aby otrzymać
jeden incydent. Każdy manifest zawiera oczekiwane rule IDs, event IDs i negatywne
warunki. Liczba alertów jest wyliczona z wersji reguł/suppression, a score z polityki;
nie wymuszamy sztucznie wartości 94 ani „jednego alertu na scenariusz”.

## Demonstracja 30–60 minut

1. 5–10 min: granice zaufania, magazyny, inbox/outbox i awaria po commicie.
2. 10–15 min: ingest, raw/normalized, threshold boundaries, Sigma i negative fixture.
3. 10–15 min: account compromise, evidence, korelacja, MITRE, risk breakdown i triage.
4. 5–10 min: hunting → bookmark → investigation → testowany draft detekcji.
5. 5–10 min: SOAR simulation, historia kroków, retry i audit, następnie trade-offy.

W PHASE 13/18 zapisujemy screenshoty **uruchomionej aplikacji**: overview, alert
explanation, timeline i playbook run. Odbiór demo obejmuje czysty start po migracjach,
login każdą rolą, wygenerowanie danych, odtworzenie po restarcie worker/Redis,
brak sieci do zewnętrznych usług oraz zgodność UI z zapisanym stanem API.
