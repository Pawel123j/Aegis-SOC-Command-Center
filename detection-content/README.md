# Detection content

Miejsce na natywne reguły, ograniczony Sigma, fixtures, lokalny katalog MITRE,
hunting queries i playbooki. Każda treść będzie miała wersję, autora, pochodzenie
i test akceptacji. Brak wykonywalnego kodu w YAML.
[Kontrakt detekcji](../docs/detection-engine.md), [SOAR](../docs/soar.md).

Etap 5 dodaje własny przykład
[encoded PowerShell](sigma/aegis_windows_encoded_powershell.yml).
Można wkleić go w zakładce Sigma i przetestować przed publikacją.
Nie jest automatycznie importowany ani włączany. Metadata `high` i tag
techniki służą do priorytetu oraz candidate association, nie potwierdzają ataku.
[Podzbiór, logsource i limity](../docs/sigma.md).
