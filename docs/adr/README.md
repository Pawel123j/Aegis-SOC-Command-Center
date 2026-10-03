# Architecture Decision Records

Decyzje przyjęte dla projektu w PHASE 0, 2026-09-24. Status „przyjęta” dotyczy
projektu, nie gotowej implementacji. Zmiana decyzji dodaje ADR zastępujący poprzedni;
nie usuwa się historii uzasadnień.

| ADR | Decyzja |
| --- | --- |
| [0001](0001-modular-monolith.md) | Modularny monolit, oddzielne procesy API/worker |
| [0002](0002-storage-ownership.md) | PostgreSQL jako stan operacyjny, ClickHouse jako archiwum |
| [0003](0003-reliable-processing.md) | Inbox/outbox, at-least-once i trwała idempotencja |
| [0004](0004-detection-semantics.md) | Jawny czas zdarzeń, explainability i ograniczony Sigma |
| [0005](0005-frontend-and-auth.md) | React SPA i sesja z krótkim access JWT oraz refresh rotation |
| [0006](0006-local-demo-and-safe-soar.md) | Lokalny single-org deployment i SOAR simulation |
| [0007](0007-incident-case-management.md) | Incydenty, transakcyjna historia, wiele źródeł live i izolacja replay |
| [0008](0008-temporal-correlation.md) | Trwałe reguły czasowe, bariera finalizacji, manifest replay i wiele dowodów |
| [0009](0009-explainable-risk.md) | Wersjonowana ocena ryzyka, jawny brak kontekstu i niezmienna historia |
| [0010](0010-versioned-attack-mappings.md) | Lokalny katalog ATT&CK, historyczne mapowania i odrębne liczniki zakresu |

Każdy nowy ADR zawiera: kontekst, decyzję, alternatywy, konsekwencje, dowód
akceptacji i warunek ponownego rozważenia.
