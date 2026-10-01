# Panel Aegis SOC

React 19.3.0, TypeScript 6.0.3, Vite 8.3.1, Node.js 24.19.0 i pnpm 11.19.0.
Panel działa za lokalnym proxy pod tym samym origin co API.

Widoki: logowanie, przegląd, zdarzenia i dowody, alerty z decyzjami analityka,
trzy wbudowane reguły, źródła z własnymi kluczami, status przetwarzania i retry.
Dane pochodzą z API; niewdrożona ocena ryzyka jest jawnie niedostępna.

```text
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm lint
pnpm format
pnpm test
```

Build tworzy `dist`, montowany tylko do odczytu w nginx. Launcher Windows buduje
go automatycznie przed uruchomieniem usług. `pnpm dev` używa API na porcie 18080;
logowanie w dev wymaga ustawienia AEGIS_PUBLIC_ORIGIN na origin dev (bez CORS
lub wyłączania kontroli CSRF). Do próby całości użyj statycznego build i proxy.

JWT i klucze ingestion są tylko w pamięci. Web Locks serializują refresh między
kartami; BroadcastChannel przekazuje bieżącą sesję. Przeglądarka bez Web Locks
wymaga ponownego logowania po wygaśnięciu access tokena. Logout potwierdza
unieważnienie sesji na serwerze; awaria pozwala ponowić tę operację.

[Instrukcja uruchomienia](../docs/local-start.md), [zakres panelu](../docs/initial-soc.md).

Konfiguracja pnpm 11 jest w `pnpm-workspace.yaml`, w tym `storeDir` dla
lokalnego cache; `.npmrc` służy w tej wersji tylko registry/auth.
Źródło: [migracja pnpm 11](https://pnpm.io/blog/releases/11.0).
