# Lokalny katalog MITRE ATT&CK

`enterprise-attack-19.2.json` jest wyciągiem metadanych z oficjalnego
Enterprise ATT&CK v19.2 w formacie STIX 2.1. Działa bez połączenia z internetem.
Zawiera 15 taktyk i 858 technik, w tym podtechniki oraz wpisy historyczne:
697 aktywnych, 149 wycofanych (`revoked`) i 12 oznaczonych `deprecated`.
Nie zawiera opisów, przykładów procedur, grup ani oprogramowania.

## Źródło i integralność

Oficjalne [wydanie v19.2](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2)
opublikowano `2026-08-05T22:58:54Z`.
[Strona aktualizacji MITRE](https://attack.mitre.org/resources/updates/)
potwierdza wydanie z sierpnia 2026.

| Pole | Wartość |
| --- | --- |
| Repozytorium | `mitre-attack/attack-stix-data` |
| Tag | `v19.2` |
| Obiekt tagu | `e400737ebdbfd36b72c63181257de7a2759c5945` |
| Commit źródła | `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4` |
| Kolekcja STIX | `x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019` |
| Wersja kolekcji | `19.2` |
| Modyfikacja kolekcji | `2026-08-05T21:33:58.496Z` |
| Pobranie przez HTTPS | `2026-10-03T14:22:46Z` |
| Rozmiar pełnego źródła | 53 835 637 bajtów |
| SHA-256 pełnego źródła | `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4` |
| Rozmiar lokalnego wyciągu | 446 846 bajtów |
| SHA-256 lokalnego wyciągu | `afc5aec04660aa0f1f2ed495247239002695574735a57133529803f08946a339` |
| SHA-256 oficjalnej licencji | `738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e` |

Źródło przypięto do
[niezmiennego adresu commitu](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json).
Pobranie używało standardowej walidacji certyfikatów TLS systemu Windows.
Sumy SHA-256 obliczono z dokładnych pobranych bajtów. GitHub API oznacza tag jako
`unsigned`; powyższe sumy służą przypięciu plików, a nie weryfikacji podpisu wydawcy.
Pełny STIX pozostaje w ignorowanym `backend/.local/mitre/` i nie trafia do obrazu aplikacji.

## Schemat wyciągu

Korzeń zawiera `schema_version: 1`, `provenance`, `tactics` i `techniques`.
Wpisy zachowują oficjalny identyfikator ATT&CK, identyfikator STIX, nazwę,
adres strony MITRE, wersję obiektu, datę modyfikacji i statusy historyczne.
Taktyki zachowują `short_name`. Techniki zachowują platformy, `tactic_ids`,
`is_subtechnique` i `parent_id` z relacji `subtechnique-of` w źródle.

Wszystkie aktywne podtechniki mają jawnego rodzica w oficjalnym źródle.
Wśród 493 podtechnik jest 477 takich relacji. Pozostałe 16 wpisów historycznych
ma `parent_id: null`, ponieważ v19.2 nie zawiera odpowiadającej relacji:
`T1053.001`, `T1070.001`, `T1070.002`, `T1547.011`, `T1562.001`, `T1562.002`,
`T1562.003`, `T1562.004`, `T1562.006`, `T1562.007`, `T1562.008`, `T1562.009`,
`T1562.010`, `T1562.011`, `T1562.012`, `T1562.013`.
Wyciąg nie odtwarza brakującego związku na podstawie samego numeru techniki.

Wersja v19 używa nazwy `Stealth` dla `TA0005` oraz dodaje
`Defense Impairment` (`TA0112`). Katalog zachowuje te oficjalne nazwy i relacje
zamiast historycznej listy 14 taktyk.
[Zmiany v19](https://attack.mitre.org/resources/updates/updates-april-2026/).

## Powtarzalne przygotowanie

Skrypt `scripts/prepare_mitre_catalog.py` używa wyłącznie biblioteki standardowej
Pythona. Czyta lokalne pliki; nie pobiera danych podczas pracy aplikacji ani
podczas przygotowania wyciągu. Przed ekstrakcją sprawdza przypięte sumy źródła
i licencji, unikalność identyfikatorów, oficjalne adresy oraz relacje rodziców.
Zapisuje UTF-8 z LF, uporządkowanymi kluczami i końcowym znakiem nowej linii.

Z katalogu głównego repozytorium, po zapisaniu oficjalnego źródła i licencji
w `backend/.local/mitre/`, można odtworzyć lub sprawdzić wyciąg:

```powershell
.\.venv\Scripts\python.exe scripts/prepare_mitre_catalog.py `
  --source backend/.local/mitre/enterprise-attack-19.2.stix.json `
  --license backend/.local/mitre/LICENSE.txt `
  --check
```

`--check` porównuje wszystkie bajty JSON, licencji i pliku sumy kontrolnej.
Pominięcie tego parametru zapisuje pliki. Domyślna data pobrania odtwarza
zatwierdzoną wersję. Nowe wydanie wymaga świadomej aktualizacji przypiętych
źródeł, sum, oczekiwanych liczebności i loadera; samo podmienienie pliku STIX
powoduje odmowę ekstrakcji.

## Znaczenie mapowań istniejących reguł

| Technika | Dowód reguły Aegis | Znaczenie |
| --- | --- | --- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Podejrzane argumenty PowerShell lub krok PowerShell w korelacji | Użycie interpretera PowerShell; etykieta nie potwierdza złośliwości polecenia. |
| [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Zdarzenie Windows 4732 dla grupy administratorów identyfikowanej przez SID | Dodanie członka lokalnej grupy podnoszącej uprawnienia. |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Co najmniej pięć nieudanych logowań w ograniczonym oknie i wspólnym zakresie | Sekwencja zgodna z próbami odgadnięcia danych logowania; brak dowodu na konkretną podtechnikę. |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Udane logowanie powiązane przez korelację z wcześniejszymi porażkami albo następującą zmianą grupy administratorów | Kontekst użycia ważnego konta; samo poprawne logowanie nie dowodzi przejęcia konta. |

`linux-root-session` pozostaje bez techniki. Jego dowód potwierdza zaakceptowaną
powłokę `sudo` albo otwarcie sesji `su` dla root, co jest również zwykłą pracą
administratora. Przypisanie [T1548.003](https://attack.mitre.org/techniques/T1548/003/)
wymagałoby przyjęcia nieudowodnionego nadużycia mechanizmu podnoszenia uprawnień
lub pamięci poświadczeń. Dodatkowy dowód i osobna, zweryfikowana reguła mogą
w przyszłości uzasadnić takie mapowanie.

## Licencja i oznaczenie

`LICENSE.txt` jest dokładną kopią
[oficjalnej licencji z przypiętego commitu](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/LICENSE.txt).

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation.

MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
