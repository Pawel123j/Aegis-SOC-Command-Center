# Walidacja repozytorium

`python scripts/validate_repository.py` (Windows: `py ...`) wymaga Python 3.11+.
Brak bibliotek zewnętrznych; skrypt niczego nie instaluje i nie zmienia plików.

Sprawdza wymagane katalogi/pliki z manifestu, UTF-8/LF/final newline, trailing
whitespace, domknięcie fenced code blocks, docelowe pliki lokalnych Markdown links,
składnię Python AST i numerację faz/wymagań. Ignoruje artefakty runtime i `.git`.
Jest to ograniczona bramka PHASE 0, nie pełny Markdown linter, test Mermaid,
skaner sekretów ani test aplikacji. Kontrole aplikacyjne zostaną dodane z kodem.
