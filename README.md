# veriscrape

[![CI](https://github.com/san64777/veriscrape/actions/workflows/ci.yml/badge.svg)](https://github.com/san64777/veriscrape/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/veriscrape)](https://pypi.org/project/veriscrape/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/san64777/veriscrape/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)

**fetch, but it tells you the truth.** A verified-fetch primitive for web scraping: every fetch
returns the bytes **plus** a portable trust verdict, so you know the moment your data is silently
wrong, not three days later through a broken downstream report.

```bash
pip install veriscrape
```

```python
import veriscrape

r = veriscrape.get("https://example.com")
r.verdict      # OK | BLOCKED | CHALLENGE | HONEYPOT | SOFT_404 | LOGIN_WALL | EMPTY_SHELL | UNVERIFIED
r.cause        # "cloudflare_challenge" | "datadome" | "js_app_shell" | ...
r.confidence   # 0.0 to 1.0
r.ok           # True only when the content is positively real
```

## The problem

Every scraping tool hands you bytes and a `200` and calls it success. In 2026 a `200 OK` is no longer
ground truth: it is often a challenge page, a login wall, a soft-404, or an empty JS shell.
Status-code retry logic (the industry default) never notices, so the corruption is stored as data and
surfaces days later. `veriscrape` classifies the response **deterministically** (no LLM) into a
verdict, with the evidence and a confidence score.

## Verdicts

| verdict | meaning |
|---|---|
| `OK` | genuine origin content |
| `BLOCKED` | a hard anti-bot deny |
| `CHALLENGE` | a JS / CAPTCHA interstitial (solvable, not content) |
| `HONEYPOT` | a decoy / AI-Labyrinth trap |
| `SOFT_404` | a "not found" served as `200` |
| `LOGIN_WALL` | a sign-in / paywall gate instead of the data |
| `EMPTY_SHELL` | a JS app skeleton with no server-rendered content |
| `UNVERIFIED` | couldn't tell, abstains rather than guess |

Detection is **two-key and conservative**: it would rather abstain (`UNVERIFIED`) than emit a
confident wrong `OK`, because a silent false `OK` is the exact failure the tool exists to prevent.
Today it detects `BLOCKED`, `CHALLENGE`, `HONEYPOT`, `SOFT_404`, `LOGIN_WALL`, and `EMPTY_SHELL` across
seven anti-bot vendors (Cloudflare, DataDome, Akamai, PerimeterX/HUMAN, Kasada, Imperva, F5 BIG-IP ASM)
and three CAPTCHA gates (reCAPTCHA, Turnstile, hCaptcha), plus vendor-agnostic content signals. A
positive `OK` is emitted for a 200 with substantial server-rendered content, but it stays
conservative: a thin or ambiguous page abstains to `UNVERIFIED` rather than risk a guessed `OK`.

## CLI

```console
$ veriscrape check https://discord.com/app
https://discord.com/app
  !! EMPTY_SHELL (js_app_shell)  confidence=0.97
  HTTP 200
```

The exit code is pipeline-friendly: `0` when content looks fine (`OK` / `UNVERIFIED`), `1` when a
problem is detected. Drop it into CI to fail a job that silently scraped a wall. `veriscrape check
--file response.html` classifies a saved response with no network; `--json` emits the record.

## The finding

We ran popular fetchers against protected sites and used veriscrape to classify what they *actually*
got back ([`benchmark/`](benchmark/), dated 2026-06-07, 9 targets × 3 requests, every result stable):

> `requests` / `curl_cffi` / `scrapling` returned **HTTP 200 "success" where the content was actually
> junk** (a JS app-shell, a login wall). **Scrapling, which markets "blocked request detection," was
> the worst (33%)**: its browser-impersonating fetch returned a `200` on a DataDome-protected page, but that 200
> was a login gate it reported as success. Status-code-only detection cannot see it. veriscrape
> flagged every one.

Reproduce: `uv run --extra benchmark python -m benchmark.run`.

For the longer story (why a 200 stopped being ground truth, and the design rules behind the verdicts),
see [why veriscrape exists](WHY.md) or the [dev.to write-up](https://dev.to/san64777/your-scraper-says-200-ok-i-measured-how-often-its-lying-3d0h).

## Use it with your existing stack

`veriscrape.get()` is the drop-in for `requests.get`, but you don't have to switch fetchers. Add
the verdict to what you already have:

```python
from veriscrape.adapters import from_requests, from_response

record = from_requests(requests.get(url))          # a requests.Response
record = from_response(status, headers, body, url=url)   # any stack (httpx, Playwright, ...)
```

Scrapy: add `veriscrape.adapters.VeriscrapeMiddleware` to `DOWNLOADER_MIDDLEWARES`, then read
`response.meta["veriscrape"]` in your spider. Same verdict object everywhere.

## Why a verdict, not just bytes

The `FetchRecord` verdict is **portable JSON you own**: the same shape travels across stacks
(`requests` / Scrapy / Playwright) and trends per-domain over time. Every fetch emits one; that shared
object is the spine. Deterministic-first by design: verdicts are computed from status / headers /
cookies / body, dated and reproducible, never a black box.

## Status

Pre-alpha · deterministic-first · Apache-2.0 · drop-in for `requests.get`.

```console
$ uv sync          # for local development from a clone
$ uv run pytest    # 125 tests
```
