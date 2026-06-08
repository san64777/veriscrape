# veriscrape: a 200 OK is not ground truth

A bare HTTP 200 is an untyped result. The status line says success, but it tells you nothing about whether the bytes underneath are the article you asked for, a login wall, a JavaScript shell with no content, or a not-found page served as 200. You take it on faith. In 2026, that faith is misplaced often enough to be a real cost.

So I ran a small experiment. Take three popular Python fetchers (`requests`, `curl_cffi`, and `scrapling`), point them at nine targets (a mix of controls and anti-bot-protected sites), three requests each, and then inspect what each one *actually* got back. Not the status code. The bytes.

A "silent failure" is a 2xx "success" whose body is junk (a JavaScript app-shell with no content, a login wall, a not-found page served as 200) that the fetcher reports as success with no signal anything is wrong. The cleanest, least-disputable case: `discord.com/app` and `web.telegram.org` both return HTTP 200 with an **empty JavaScript app-shell**, a mount point and a wall of scripts, zero server-rendered content. Every status-code-only fetcher (`requests`, `curl_cffi`, `scrapling`) stores that husk as a successful page. The status says success, the bytes are a skeleton, and the corruption is saved as data.

This is a category-wide, structural blind spot, not a knock on any one tool: status-code retry logic is blind to content-level failure by construction, so any fetcher built on it inherits the gap.

A note on how I know, because it matters more than any single number. I captured the raw body of every fetch and labeled each one independently of veriscrape, then compared. That process caught a mistake in an earlier draft of this writeup: a cell I had reported as a competitor's "silent failure" on `g2.com` was actually a *veriscrape* false positive. The real G2 homepage had come back (the anti-bot let the fetch through), and veriscrape had mislabeled the content-rich homepage as a login wall. I fixed the detector (the real homepage now classifies as `OK`) and retracted the claim. That is the whole thesis turned on its author: the tool exists to flag silently-wrong data, and the discipline has to apply to its own output first. A confident, wrong verdict is the exact failure veriscrape exists to prevent, so when it cannot stand behind one it abstains (`UNVERIFIED`) rather than guess.

## Why this happens

In 2026 a 200 OK is no longer ground truth. It is often a challenge page, a login wall, a soft-404, or an empty JS shell. Status-code retry logic, the industry default, never notices. So the corruption is stored as if it were real data, and surfaces days later as a quietly wrong downstream report. The failure is not that the fetch broke. The failure is that it looked fine.

## The primitive

veriscrape is a verified-fetch primitive. Every fetch returns the bytes plus a portable, deterministic trust verdict.

```python
import veriscrape

r = veriscrape.get("https://example.com")
r.verdict     # OK BLOCKED CHALLENGE HONEYPOT SOFT_404 LOGIN_WALL EMPTY_SHELL UNVERIFIED
r.cause       # e.g. "cloudflare_challenge", "datadome", "js_app_shell", "login_wall"
r.confidence  # 0.0 to 1.0
r.ok          # True ONLY when r.verdict is OK
r.evidence    # the exact markers matched, for audit
```

The verdicts cover eight states: `OK` (genuine origin content), `BLOCKED` (a hard deny), `CHALLENGE` (a JS or CAPTCHA interstitial), `HONEYPOT` (a decoy or AI-Labyrinth trap), `SOFT_404`, `LOGIN_WALL`, `EMPTY_SHELL` (a JS skeleton with no server-rendered content), and `UNVERIFIED`.

`get()` fetches with `curl_cffi`, then runs the deterministic classifier over the response. The browser-like TLS in `get()` exists only so you are not labeled on a TLS signal alone, before the classifier ever sees the body. The verdict is portable JSON you own (the `FetchRecord`): the same shape travels across `requests`, Scrapy, and Playwright, and trends per-domain over time.

One design rule worth stating plainly, because a truth-telling tool has to tell the truth about itself: it abstains over guessing. `get()` returns a positive `OK` only for a 200 that is a real document with substantial server-rendered content, the inverse of an empty shell. Anything short, ambiguous, or disqualified (a padded soft-404, a paywall teaser, a suspended or error page served as a 200) comes back `UNVERIFIED`, not `OK`, so `r.ok` is `True` only on that affirmative verdict. `UNVERIFIED` is a real verdict and it is not `ok`. A confident, wrong `OK` is the exact failure veriscrape exists to prevent, so when the evidence is thin it would rather say `UNVERIFIED` than bless the page.

## The rigor

Detection is deterministic. No LLM. Verdicts are computed from status, headers, cookies, and body, and the `evidence` dict shows exactly which markers matched, so a verdict is auditable and never a black box.

The core discipline is a two-key rule. A vendor fingerprint alone (`Server: cloudflare`, a `cf-ray` header, a `_px` cookie, an `x-kpsdk` header) appears on allowed pages too, so it is never a verdict by itself. A real verdict needs the vendor gate *and* a challenge-or-block-specific marker on a genuine mitigation response (the right status, a real code assignment, not a quoted substring a blog post happens to contain).

Coverage today is 14 detectors: seven anti-bot vendors (Cloudflare, DataDome, Akamai, PerimeterX/HUMAN, Kasada, Imperva/Incapsula, F5 BIG-IP ASM), three CAPTCHA gates (reCAPTCHA, Turnstile, hCaptcha, detected as a full-page gate and distinguished from a widget merely embedded in a normal form), plus honeypot, login-wall, soft-404, and empty-shell content verdicts. Every detector ships with allowed-page fixtures, real pages from the same vendors that are not challenges or blocks, and the test suite fails if any of them trips a verdict. That discipline is the one I care about most: a truth-telling tool that cries wolf is worthless, which is the whole reason for the two-key rule.

## The five-minute drop-in

`veriscrape.get()` is a drop-in for `requests.get`. You do not have to switch fetchers either:

```python
from veriscrape.adapters import from_requests, from_response

record = from_requests(requests.get(url))                 # a requests.Response
record = from_response(status, headers, body, url=url)    # httpx, Playwright, anything
```

For Scrapy, add `veriscrape.adapters.VeriscrapeMiddleware` to `DOWNLOADER_MIDDLEWARES` and read `response.meta["veriscrape"]` in the spider. There is a CLI too: `veriscrape check <url>` exits 0 when content looks fine (`OK` or `UNVERIFIED`) and 1 when a problem is detected, so it drops into CI to fail a job that silently scraped a wall. `veriscrape check --file response.html` classifies a saved response with no network.

`pip install veriscrape` (0.1.0, Apache-2.0, Python 3.12+). It is early, and I would genuinely like the benchmark and the detectors torn apart. The whole point is to not lie to you about your data, which starts with not lying about the tool.

---

*Written by Sanjay Chauhan, who builds reliability and data-integrity primitives for data pipelines. veriscrape is open source under Apache-2.0: https://github.com/san64777/veriscrape . Reach me at san64777@gmail.com.*

<!-- TODO(author): add a LinkedIn or personal-site URL here if you want one in the footer. -->
