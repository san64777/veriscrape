# Contributing to veriscrape

Thanks for your interest. veriscrape is a verified-fetch primitive: every fetch returns
the bytes plus a portable trust verdict, so you know the moment your data is silently
wrong. Contributions are welcome. Please read this first so your PR goes smoothly.

## Project philosophy (please respect it)

- **Abstain over guess.** A confident but wrong verdict is the one failure this project
  exists to prevent. `UNVERIFIED` is a real, correct answer when the signals are not
  conclusive. A false positive (crying wolf on a fine page) is the cardinal sin, worse
  than a miss.
- **Deterministic first, no LLM.** Verdicts are computed from status, headers, cookies,
  and body. They must be dated and reproducible. No models, no extra network calls.
- **Detect with two keys, never one.** A vendor fingerprint alone (a `Server` header, a
  cookie, even a challenge-platform reference) is present on allowed pages too. Pair it
  with a challenge-specific marker, and prefer a real `src=` or assignment over a bare
  substring that prose could quote.
- **Drop-in, never a migration.** The `veriscrape.get` and `classify` API should stay a
  five-minute paste-in for `requests.get`. Do not break it.
- **Permissive only.** The runtime dependency tree must stay permissive (MIT / BSD /
  Apache / MPL). No GPL / AGPL / LGPL / SSPL, even transitively. CI enforces this.
- **Reliability framing, not "bypass."** The edge is data integrity and provenance.

## Development setup

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/<your-fork>/veriscrape
cd veriscrape
uv sync
uv run pytest
```

## Before you open a PR

Run the full quality bar locally. All of it must be green:

```bash
uv run ruff check src tests     # lint
uv run mypy src                 # types
uv run pytest                   # tests (no network needed; detectors run on captured fixtures)
uv run pip-licenses --fail-on='GPL;AGPL;LGPL;SSPL' --partial-match   # license gate
```

- **Add tests** for any behavior change. We use TDD: write the failing test against a
  captured fixture first, then the rule.
- **New detector?** It must use the two-key rule and ship a false-positive guard fixture
  (a real allowed page that must NOT fire). Detectors are pure functions of
  `(status, headers, body)`.
- **Conventional commit messages** (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).

## Workflow

1. **Fork** and create a branch (`git checkout -b feat/my-change`).
2. Make your change with tests.
3. Run the quality bar above.
4. Open a **Pull Request** against `main`. CI (lint, types, tests, license gate) runs
   automatically.
5. A maintainer reviews and merges. Thanks!

## Reporting bugs and detection misses

Open an issue. For a wrong verdict, attach a **non-sensitive** reproduction (a public URL,
or a captured status + headers + body with any PII or secrets removed).

## License

By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license.
