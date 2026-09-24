# ADR 0005 — SPA i uwierzytelnienie

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

## Kontekst

Narzędzie SOC jest prywatną aplikacją analityczną z intensywną pracą na tabelach,
filtrach i timeline. Nie potrzebuje SEO ani dwóch różnych backendów aplikacyjnych.

## Decyzja

React + TypeScript + Vite, statyczny build za tym samym origin co FastAPI. Klient
API generowany z OpenAPI, serwerowa kontrola ról, dark mode i dostępna nawigacja.
Access JWT żyje krótko i pozostaje w pamięci przeglądarki. Rotowany opaque refresh
jest w HttpOnly Secure cookie; w bazie jedynie hash. Mutacje cookie-auth wymagają
CSRF protection i kontroli origin. Szczegóły i okresy: [security](../security.md).

## Alternatywy i konsekwencje

Next.js dodałby runtime server-side bez potrzeby SSR. JWT w localStorage utrwalałby
token dostępny dla skryptów, a pojedynczy długowieczny JWT komplikowałby revocation.
Opaque session także byłaby poprawna; JWT access zachowuje preferencję użytkownika,
lecz sprawdzanie aktywnej sesji/roli w backendzie oznacza, że system nie jest bezstanowy.

Kosztem memory-only access jest kontrolowany refresh po przeładowaniu i koordynacja
wielu kart podczas rotacji. Nie traktujemy CORS ani ukrytego przycisku jako permission.

## Dowód i ponowna ocena

E2E login/refresh/logout/reuse, równoległe karty, CSRF i natychmiastowe odebranie roli.
Nowy ADR, jeśli zewnętrzny IdP/OIDC lub wiele originów stają się wymaganiem.
