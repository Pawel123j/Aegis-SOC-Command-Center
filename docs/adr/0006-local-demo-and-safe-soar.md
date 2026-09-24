# ADR 0006 — lokalne demo i SOAR simulation

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

## Kontekst

Demo musi działać bez infrastruktury klienta, sekretów dostawców TI i przypadkowych
skutków ubocznych. Zadaniem jest pokazanie procesu SOC, a nie zdalne zarządzanie hostami.

## Decyzja

Docker Compose na jednym hoście, jedna organizacja, offline runtime po pobraniu
obrazów/zależności. Generator wysyła wyłącznie raw events przez publiczny kontrakt
ingestion. Skończone, wersjonowane demo datasets używają tego samego pipeline i
izolowanego `run_id`. Nie seedujemy alertów ani case. Lokalny katalog MITRE i IOC
jest częścią wersjonowanego contentu.

SOAR używa rejestru jawnych akcji. Każda akcja infrastrukturalna jest mockiem,
zapisuje zamierzony skutek i wynik simulation; brak shell/SSH/real firewall API.
`notify_analyst` tworzy lokalne powiadomienie aplikacji. Przyszłe realne integracje
wymagają nowej granicy uprawnień i osobnego ADR.

## Alternatywy i konsekwencje

Statyczne seedy alertów dawałyby łatwe UI, ale nie dowodziły detekcji. Zewnętrzne
API TI tworzyłyby koszty, limity i zależność internetową. Realne blokowanie IP jest
niepotrzebne dla celu portfolio. Demo nie dowodzi działania produkcyjnych konektorów.

## Dowód i ponowna ocena

Siedem scenariuszy end-to-end i normal activity, powtórzenie tego samego run bez
duplikacji, brak ruchu do zewnętrznych usług w runtime, odtwarzalny wynik reguł.
Pełna demonstracja 30–60 min kończy się analizą trade-offów oraz dowodami z testów.
