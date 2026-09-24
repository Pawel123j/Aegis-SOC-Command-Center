# Raport stanu początkowego

Data inspekcji: 2026-09-24. Zakres: wskazany przez użytkownika katalog
`C:\Users\pawel\OneDrive\Aegis SOC Command Center` oraz instrukcje AGENTS.md
w katalogach nadrzędnych. Raport opisuje stan **przed dodaniem PHASE 0**.

## Dowody

| Kontrola | Wynik |
| --- | --- |
| `Get-ChildItem -Force` | Pusta lista, także bez plików ukrytych |
| `Test-Path .git` | False |
| `git rev-parse --show-toplevel` | Katalog ani jego rodzice nie są repozytorium Git |
| Wyszukiwanie manifestów i README przez `rg --files` | Brak plików |
| AGENTS.md w workspace i sprawdzonych rodzicach | Nie znaleziono |
| Kod aplikacji, testy, migracje, pipeline CI | Nie istnieją |

Nie ma istniejących funkcjonalności, danych ani zmian użytkownika, które należałoby
przenosić lub nadpisywać. Nazwa katalogu nie oznaczała istniejącego projektu Git.
Załącznik użytkownika jest specyfikacją wymagań, nie kodem aplikacji.

## Środowisko lokalne

| Narzędzie | Zaobserwowany stan | Znaczenie |
| --- | --- | --- |
| Git | 2.55.0.windows.3 | Dostępny; brak skonfigurowanych user.name/user.email |
| Python Launcher | Python 3.14, 32-bit | Nadaje się do walidatora stdlib; nie jest docelowym runtime backendu |
| Node | 24.19.0, runtime narzędziowy | Dostępny; nie uruchamiano frontendu |
| npm, uv, Ruff | Nie znaleziono na PATH | Wdrożenie narzędzi aplikacji należy do kolejnych etapów |
| Docker CLI | 29.7.2, context desktop-linux | Klient dostępny |
| Docker Compose | v5.5.1 | Polecenie dostępne |
| Docker Engine | Brak połączenia z dockerDesktopLinuxEngine | Nie można obecnie wykonać testów kontenerowych |

Samego wykrycia polecenia `python` nie potraktowano jako dowodu działania:
na PATH znajdują się też aliasy WindowsApps. W PHASE 0 użyto launchera `py`.
Nie uruchamiano Docker Desktop ani nie instalowano globalnych pakietów.
OneDrive może opóźniać synchronizację wielu małych plików; docelowe dane baz będą
w nazwanych wolumenach Docker, nie w folderze synchronizowanym z chmurą.

## Brakujące komponenty

| Obszar | Braki | Plan |
| --- | --- | --- |
| Fundament | Git, konwencje, ADR, dependency locks, DI, konfiguracja | 0–1 |
| Dane i ingest | Schematy, migracje, inbox/outbox, batch API, parsery i kwarantanna | 1–3 |
| Detection | Ewaluacja, stan okien, wersje reguł, Sigma, fixtures | 4 |
| SOC | Alerty, korelacja, case management, attack chain, risk | 5–9 |
| Intelligence | IOC, reputacja lokalna i dopasowanie | 10 |
| Hunting / SOAR | Zapytania, investigations, draft rules, playbook runner | 11–12 |
| UI i demo | Wszystkie widoki, auth flow, scenariusze, prawdziwe API | 13–14 |
| Eksploatacja | Metryki, logi, limity, retencja, odtwarzanie po awarii | 1–16 |
| Jakość | Testy domeny/API/integracji/E2E, skany, build, CI i branch protection | 1–20 |
| Portfolio | Instrukcja uruchomienia, screenshoty i zweryfikowany scenariusz prezentacji | 18–20 |

Szczegółowe przypisanie każdego wymagania zawiera
[macierz](requirements-traceability.md). Żaden z braków funkcjonalnych nie jest
uznany za rozwiązany przez sam opis architektury.

## Rekomendacja

Rozpocząć od PHASE 0 i testowalnych kontraktów. Nie tworzyć pozornego dashboardu,
gotowych alertów ani pustych endpointów udających działanie platformy.
Najważniejsze ryzyka przed implementacją to: utrata danych między bazą a kolejką,
podwójne alerty przy retry, niepoprawna semantyka czasu, nadmierna korelacja wspólnych
adresów IP oraz eskalacja uprawnień przez playbook lub importer reguł.

PHASE 0 dodaje wyłącznie dokumentację, strukturę katalogów i bramkę jakości tego
etapu. Wynik wykonania jest oddzielony od tego baseline w [raporcie walidacji](validation.md).
