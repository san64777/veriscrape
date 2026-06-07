## What and why

<!-- What does this change, and why? Link any related issue. -->

## Checklist

- [ ] Tests added or updated (TDD: write the failing test against a captured fixture first)
- [ ] `uv run ruff check src tests` is clean
- [ ] `uv run mypy src` is clean
- [ ] `uv run pytest` is green
- [ ] Conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- [ ] For a new or changed detector: it uses the two-key rule (a vendor fingerprint plus a
      challenge-specific marker), and it ships a false-positive guard fixture (an allowed page
      that must NOT fire). A confident wrong verdict is the cardinal sin here; abstaining is fine.
