# ADR 0004 — deterministyczna detekcja zamiast ukrytych heurystyk

Status: przyjęta w projekcie PHASE 0. Data: 2026-09-24.

## Kontekst

Logi przychodzą poza kolejnością; retry i import historyczny nie mogą zmieniać
znaczenia reguły. Alert musi dać się wyjaśnić i odtworzyć po zmianie reguł i IOC.

## Decyzja

Wersjonowany natywny AST, czysty evaluator i immutable evidence. Event-time windows,
jawne allowed lateness, trwały watermark i zamknięte replay datasets. Threshold
ma ruchome okno; suppression bucket ogranicza alerty bez zmiany predykatu. Korelacja
wymaga wspólnej tożsamości i dowodu przejścia, nie tylko wspólnego IP/MITRE.
Ryzyko jest jawną funkcją z wersją i wkładami, bez LLM.

Sigma v1 to wąski, walidowany subset z błędami dla nieobsługiwanych konstrukcji.
Nie deklarujemy pełnej zgodności; profil oraz koszt restrykcyjnego importu opisuje
[detection engine](../detection-engine.md). Nie wykonujemy YAML jako kodu.

## Alternatywy i konsekwencje

Processing-time uprościłby stan, ale dawałby inne wyniki dla tego samego śladu.
Natychmiastowe provisional alerts wymagają retract/update przy spóźnionych logach;
pierwsza wersja wybiera finalizację po 120 s bufora plus backlog. Replay zamkniętego
demo usuwa oczekiwanie bez omijania silnika. Pełna Sigma i dowolny regex są droższe
do poprawnego zabezpieczenia; rozwijamy subset dopiero z fixtures.

## Dowód i ponowna ocena

Te same wersje i zamknięty zbiór eventów dają te same logiczne wyniki dla wszystkich
kolejności dostarczenia. Testy obejmują granice czasu, NAT, late pierwszy element
sekwencji i podwójne evidence. Zmiana polityki finalizacji wymaga osobnego ADR.
