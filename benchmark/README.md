# benchmark: the reliability finding

**The robust, independently-labeled finding:**

> `discord.com/app` and `web.telegram.org` return **HTTP 200 with an empty JavaScript app-shell**: no
> server-rendered content, just a mount point and a wall of scripts. Every status-code-only fetcher
> (`requests`, `curl_cffi`, `scrapling`) stores that husk as a successful page. The status says
> success, the bytes are a skeleton, and the corruption is saved as data with no signal anything
> went wrong.

A **silent failure** is the whole point: a `200 OK` whose body is actually a block / challenge /
login gate / empty shell / soft-404, returned unflagged and stored as data.

> **Retraction (2026-06-08).** An earlier cut named `scrapling` "the worst (33%)" on the basis of a
> g2.com cell. Independent re-labeling of the captured bodies showed that cell was a **veriscrape
> false positive**: scrapling fetched the real, content-rich G2 homepage (the anti-bot let it
> through) and veriscrape mislabeled it as a login wall. The detector is fixed (that homepage now
> classifies `OK`), the claim is retracted, and the scrapling-specific framing is dropped. See the
> CORRECTION banner in [`results-2026-06-07.md`](results-2026-06-07.md).

## How it measures (de-circularized)

For each (tool x target): fetch with the tool, **capture the raw body** to `captures/<date>/`
(local), record what `veriscrape` predicts, and label each body **independently of veriscrape**
(`labels-<date>.toml`). The silent-failure rate is scored against the independent label
(`summarize_truth`), and `classify_agreement` reports separately how often veriscrape matched that
label (its real, non-circular accuracy). This removes the self-grading the first cut relied on.

## Run it

```bash
uv run --extra benchmark python -m benchmark.run --date 2026-06-08            # capture + predict
uv run --extra benchmark python -m benchmark.run --date 2026-06-08 --render   # after hand-labeling
```

Edit [`targets.toml`](targets.toml) to change the matrix. Scoring lives in [`score.py`](score.py)
(unit-tested in `tests/test_benchmark_score.py`).

## Honest caveats (read before citing)

- **Independent labels required.** A published silent-failure or accuracy number is only valid once
  `labels-<date>.toml` is filled by hand-reading the captured bodies. Until then the truth-scored
  numbers are empty by design.
- **Captures are local.** `captures/` is gitignored; the raw bodies are the local evidence behind the
  labels, not a committed dataset.
- **Tool / target rework pending.** A clean re-cut wants real article URLs (not `/login`, a weak
  silent-failure proxy), a live soft-404, and a browser-rendering fetcher, plus more runs across time
  and IPs. `nowsecure.nl` is an ambiguous turnstile demo; treat it with care.
- Public targets only; one respectful GET per cell.
