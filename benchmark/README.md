# benchmark: the neutral reliability finding

**The headline (2026-06-07, 9 targets × 3 requests each, every result 3/3 stable):**

> Three popular fetchers returned **HTTP 200 "success" where the content was actually junk** (a JS
> app-shell, a login wall) and reported success. **Scrapling, which markets "blocked request
> detection," was the *worst* (33%)**: its quiet fetch slipped a `200` past g2.com's DataDome
> block, but that 200 was a login gate it called success. Status-code-only detection cannot see it.
> veriscrape flagged every one.

| tool | silent-failure rate (N=3, all 3/3 stable) |
|---|---|
| `requests` | 11% |
| `curl_cffi` | 22% |
| `scrapling` (markets block detection) | **33%** |

A **silent failure** is the whole point: a `200 OK` whose body is actually a block / challenge /
login gate / empty shell / soft-404, returned unflagged and stored as data. See
[`results-2026-06-07.md`](results-2026-06-07.md) for the full dated table.

## What it measures

For each (tool × target): fetch with the tool, classify the **real** response (status + headers +
body) with `veriscrape`, and mark a **silent failure** when a 2xx response carries a negative
verdict the tool did not flag.

## Run it

```bash
uv run --extra benchmark python -m benchmark.run            # writes results-<date>.json + .md
uv run --extra benchmark python -m benchmark.run --date 2026-06-07
```

Edit [`targets.toml`](targets.toml) to change the matrix. Scoring lives in
[`score.py`](score.py) (unit-tested in `tests/test_benchmark_score.py`).

## Honest caveats (read before citing)

- **Tools so far: `requests` + `curl_cffi`** (naive baselines). `scrapling` is wired in (it *claims*
  block detection, but its mechanism is status-code-only, so it would still miss the 200 husk/gate);
  `crawl4ai` / `browser-use` / `Firecrawl` are the next rows.
- **veriscrape is the labeler.** Verdicts were spot-validated against live sites (g2.com → DataDome
  403; discord → empty shell) but should be hand-verified before any public publication.
- **N = 3 per cell, all results 3/3 stable** this run (the harness reports the modal verdict +
  stability). A larger public claim still wants more runs spread across time and IPs. (Honest
  artifact: `requests` got rate-limited (429) on the HN login after 3 quick hits, itself a
  non-silent failure, since the status reveals it.)
- **Dated snapshot.** `nowsecure.nl` was *passing* (allowed) at capture time; anti-bot rots, so re-run before quoting.
- Public targets only; one respectful GET per cell.

See [`../research/benchmark-methodology.md`](../research/benchmark-methodology.md) for the full spec.
