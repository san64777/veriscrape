"""Deterministic verdict classification: the brain of veriscrape.

Given the raw response (status, headers, body), decide which Verdict it is,
using dated, reproducible signals only. No LLM in M1.

Detectors are pure functions of (status, headers, body), built test-first
against captured fixtures in ``tests/fixtures/``. ``classify`` runs them in
order and returns the first positive verdict; if none fires it abstains
(UNVERIFIED). A confident-but-wrong OK is the exact failure we prevent.

Design rule (proven against live data + adversarial review): detect with TWO
keys, never one. A vendor fingerprint alone (``Server: cloudflare``, a
``cf-ray`` header, even a ``cdn-cgi/challenge-platform`` body reference) is
present on *allowed* pages too. And a body marker must be a real *assignment*
on a real challenge *response*, not a bare substring. Otherwise an allowed
page that merely quotes ``window._cf_chl_opt`` (a blog, the CF docs, a Wayback
snapshot) is misclassified.
"""

from __future__ import annotations

import re
from typing import Any

from selectolax.parser import HTMLParser

from .record import Verdict

_ABSTAIN: tuple[Verdict, None, float, dict] = (Verdict.UNVERIFIED, None, 0.0, {})

# A genuine challenge ASSIGNMENT (`window._cf_chl_opt = {`), not a prose mention of the token.
_CF_CHL_ASSIGN = re.compile(r"window\._cf_chl_opt\s*=\s*\{")
# DataDome markers. `rt` is the response-type inside `var dd={...}`: 'c'=captcha, 'b'=block.
# captcha-delivery.com is the challenge-delivery host, required as a real `src=` resource (not a
# CSP/preconnect allow-list mention, which ships on allowed pages too).
_DD_RT = re.compile(r"""['"]rt['"]\s*:\s*['"]([a-z])['"]""", re.I)
_DD_CAPTCHA_SRC = re.compile(r"""src\s*=\s*['"]https?://[a-z0-9.-]*captcha-delivery\.com""", re.I)
# A DataDome mitigation is never a 2xx.
_DD_MITIGATION_STATUSES = frozenset({401, 403, 429})

# Akamai deny page: the "Reference #<digits>.<hex>.<digits>.<hex>" tracking id, plus Bot Manager cookies.
_AK_REFERENCE = re.compile(r"Reference\s*#\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+", re.I)
_AK_COOKIES = ("_abck=", "bm_sz=", "ak_bmsc=", "bm_sv=")

# PerimeterX / HUMAN. The _px* cookie AND sensor JS are on allowed pages, so a challenge needs a
# non-2xx status AND a challenge-specific marker (NOT generic 'press & hold' UI copy).
_PX_COOKIES = ("_px3=", "_px2=", "_pxhd=", "_pxvid=", "_px=")
_PX_CHALLENGE_STATUSES = frozenset({403, 429})
_PX_VERIFY = re.compile(r"verify you are (?:a )?human", re.I)
_PX_CAPTCHA_SRC = re.compile(r"""src\s*=\s*['"]https?://[a-z0-9.-]*captcha\.px-cdn\.net""", re.I)
# Sensor JS as a vendor fingerprint (used when the _px cookie is request-only). The ASSIGNMENT form,
# so a blog mentioning the host in prose does not match. NOT a challenge marker (it's on allowed pages).
_PX_SENSOR = re.compile(r"_pxappid\s*=|client\.perimeterx\.net|collector-px[a-z0-9]*\.perimeterx\.net", re.I)
_PX_DENY = ("access to this page has been denied", "you don't have permission to access")
# Kasada. x-kpsdk-* is the vendor gate (present on cleared 200s too); a mitigation is non-2xx AND
# carries the obfuscated proof-of-work script (/ips.js or a GUID-style /p.js).
_KASADA_STATUSES = frozenset({403, 429})
_KASADA_POW = re.compile(r"""src\s*=\s*['"][^'"]*/(?:ips|p)\.js(?:[?'"]|$)""", re.I)

# Imperva / Incapsula. Cookies/headers are on allowed pages; the mitigation marker is the key.
# NOT '_Incapsula_Resource': that is the client-side SENSOR script (`<script src=
# "/_Incapsula_Resource?SWJIYLWA=…">`) Imperva injects into EVERY protected page (allowed 200s
# included) for fingerprinting. Keying on it is the same sensor-on-allowed-pages trap DataDome had.
# The block/challenge page is distinguished by block-ONLY text ('Request unsuccessful', 'Incapsula
# incident ID') and the iframe's 'incident_id=' param (absent on allowed pages).
_INCAP_MARKERS = ("incapsula incident id", "request unsuccessful", "incident_id=")
# F5 BIG-IP ASM deny template, F5-ASM-specific (BIG-IP TS/BIGipServer cookies are just the LB).
# The support-ID line carries a real ": <digits>"; prose ("quote your support ID to the help desk")
# does not: the discriminator against pages that merely TALK about the F5 message.
_F5_SUPPORT_ID = re.compile(r"support\s*id\s*(?:is)?\s*:\s*\d", re.I)

# CAPTCHA interstitial: a full-page reCAPTCHA / Turnstile GATE. The widget ALONE is on ordinary
# login/signup/contact forms and demos, so a gate also needs to be content-light WITH gate copy.
_RECAPTCHA = re.compile(
    r"(?:www\.google\.com|gstatic\.com|recaptcha\.net)/recaptcha/"
    r"|class=[\"'][^\"']*g-recaptcha"
    r"|grecaptcha\.(?:render|execute|enterprise)",
    re.I,
)
_TURNSTILE = re.compile(
    r"challenges\.cloudflare\.com/turnstile|class=[\"'][^\"']*cf-turnstile", re.I
)
_HCAPTCHA = re.compile(
    r"(?:js\.)?hcaptcha\.com/1/api\.js|class=[\"'][^\"']*h-captcha", re.I
)
_CAPTCHA_GATE_COPY = (
    "verify you are human", "verify you are a human", "verify you're human",
    "verify that you are human", "verify that you are a human",
    "verify you are not a robot", "verify you're not a robot",
    "confirm you are not a robot", "prove you are not a robot",
    "complete the captcha", "complete the security check", "complete this captcha",
    "before you can continue", "before you continue", "additional security check",
    "security check is required", "confirm you are human", "prove you are human",
    "complete the challenge", "solve the captcha", "verify to continue",
)
_CAPTCHA_MAX_VISIBLE = 600
# A true GATE has no DATA-entry form: you solve the captcha and proceed, the widget IS the page.
# A normal form that merely embeds a captcha (newsletter / comment / contact / signup / login) COLLECTS
# data, so it carries text/email/password/etc. fields, a textarea, or a select. The captcha-response
# <input type="hidden">, and submit/button/checkbox/radio, are not data-entry: they exist on a gate too.
_CAPTCHA_DATA_INPUT_TYPES = frozenset(
    {"text", "email", "password", "tel", "url", "number", "search",
     "date", "datetime-local", "month", "week", "time"}
)


def _has_data_entry_field(body: str) -> bool:
    """True if the page collects user data (a real form), not just a captcha to solve.

    Counts text-like ``<input>``s, any ``<textarea>``, and any ``<select>``. Hidden/submit/button/
    checkbox/radio inputs are excluded: those appear on a bare captcha gate too.
    """
    tree = HTMLParser(body)
    for node in tree.css("input"):
        if (node.attributes.get("type") or "text").lower() in _CAPTCHA_DATA_INPUT_TYPES:
            return True
    return tree.css_first("textarea") is not None or tree.css_first("select") is not None

# Honeypot: a cluster of INVISIBLE nofollow trap links into a same-host DEEP maze.
# Inline hide-from-humans styles (a trap author can slip past by dropping "px" or using font-size:0).
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*(?:hidden|collapse)"
    r"|opacity\s*:\s*0(?![.\d])"
    r"|font-size\s*:\s*0(?![.\d])"
    r"|(?:width|height)\s*:\s*(?:0(?![.\d])|[01]px)"
    r"|clip\s*:\s*rect\(\s*0[ ,]"
    r"|clip-path\s*:\s*inset\(\s*(?:100%|50%)"
    r"|transform\s*:[^;]*scale\(\s*0\s*\)"
    r"|(?:left|top|text-indent)\s*:\s*-\d{3,}(?:px|em|rem|%)",
    re.I,
)
_HONEYPOT_MIN_TRAP_LINKS = 3

# Login wall. Intent phrases are ANCHORED gate language (not a bare "to continue reading" CTA).
_LOGIN_INTENT = (
    "sign in to continue", "log in to continue", "sign in to read", "log in to read",
    "sign in to continue reading", "subscribe to continue reading", "subscribe to read",
    "this content is for subscribers", "you must be logged in", "log in to view", "sign in to view",
)
_SIGNIN_CUE = ("sign in", "log in", "login", "signin")
# Account-management forms have a password field in main content but are NOT a sign-in gate.
# (A "forgot your password?" LINK is excluded on purpose: login pages routinely carry it.)
_ACCOUNT_MGMT_MARKERS = (
    "reset your password", "change password", "current password", "confirm password",
    "new password", "security settings",
)
# Hosted-auth / SSO signals for the password-free (OAuth) path.
_AUTH_VENDOR_URLS = re.compile(
    r"accounts\.google\.com/o/oauth2|appleid\.apple\.com/auth|login\.microsoftonline\.com|"
    r"[a-z0-9.-]+\.okta\.com|[a-z0-9.-]+\.auth0\.com|[a-z0-9.-]+\.onelogin\.com|github\.com/login/oauth",
    re.I,
)
_AUTH_FORM_ACTION = re.compile(
    r"""<form[^>]+action=["'][^"']*(?:/login|/signin|/sign-in|/session|/auth|/sso|wp-login)""", re.I
)
_SSO_BUTTON = re.compile(
    r"(?:sign in|log in|continue|sign up)\s+with\s+(?:google|apple|microsoft|github|sso|okta|facebook)", re.I
)
# A real login page is content-light; a content article that merely has a header login box is not.
_LOGIN_WALL_MAX_VISIBLE = 1000

# Soft-404: a 200 that is really a "not found" / parked placeholder. Markers checked in MAIN content.
_NOT_FOUND_MARKERS = (
    "page not found", "page does not exist", "page doesn't exist",
    "page you requested could not be found", "page you are looking for",
    "page can't be found", "page cannot be found", "page no longer exists",
    "the requested url was not found", "404 not found", "error 404",
    "we couldn't find that page", "couldn't find the page", "that page doesn't exist",
    "this page isn't available", "page not available",
)
_PARKED_MARKERS = (
    "this domain is for sale", "buy this domain", "domain is for sale",
    "domain is parked", "this domain was parked", "domain parking", "parked free",
)
_SOFT_404_MAX_VISIBLE = 1200
# A real Cloudflare JS/managed challenge is never served as 2xx; it is 403 (or 503 pre-2023, or 429).
_CF_CHALLENGE_STATUSES = frozenset({403, 429, 503})

# Empty-shell tuning. A low floor (real SPA bootstraps can be ~360 bytes, e.g. an Angular <app-root>
# + module script); the empty-husk mount + a <script> are the real guards, not the byte count.
_SHELL_MIN_BYTES = 256
_SHELL_MAX_VISIBLE = 200
# Common SPA mount points: an *empty husk* one of these is a JS-app-skeleton signal.
_MOUNT_IDS = ("root", "app", "app-mount", "__next", "__nuxt", "___gatsby", "q-app", "app-container")
# Custom-element mounts (Angular <app-root>, web-component selectors like <cm-certemy>) are caught
# generically (any empty-husk hyphenated tag) in _detect_empty_shell, not by a fixed list.
_JS_REQUIRED_MARKERS = (
    "enable javascript",
    "you need to enable",
    "please enable js",
    "doesn't work properly without javascript",
    "requires javascript",
)


def _lower_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def _detect_cloudflare_challenge(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """Cloudflare managed/JS challenge ('Just a moment...'), via the two-key rule."""
    h = _lower_headers(headers)
    body = body or ""

    # KEY 1, vendor gate: is this Cloudflare at all? (Never a block signal by itself.)
    if "cloudflare" not in h.get("server", "").lower() and "cf-ray" not in h:
        return None

    # KEY 2, path A, the authoritative header. Cloudflare sets `cf-mitigated: challenge`
    # only when it serves a challenge, so it stands alone (header-based, very low FP risk).
    if h.get("cf-mitigated", "").lower() == "challenge":
        return Verdict.CHALLENGE, "cloudflare_challenge", 0.98, {"cf-mitigated": "challenge"}

    # KEY 2, path B, the interstitial body, but only on a *real* challenge response:
    # a genuine _cf_chl_opt assignment AND the challenge-platform script AND a blocky status.
    # This rejects allowed 200 pages that merely quote the token, and archived/proxied snapshots.
    if (
        status in _CF_CHALLENGE_STATUSES
        and _CF_CHL_ASSIGN.search(body)
        and "cdn-cgi/challenge-platform" in body
    ):
        return (
            Verdict.CHALLENGE,
            "cloudflare_challenge",
            0.97,
            {"body": "window._cf_chl_opt={…}", "co_marker": "cdn-cgi/challenge-platform", "status": status},
        )

    return None


def _detect_cloudflare_block(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """Cloudflare WAF hard block ('Sorry, you have been blocked'). BLOCKED, not CHALLENGE."""
    h = _lower_headers(headers)
    body = body or ""

    # KEY 1, vendor gate.
    if "cloudflare" not in h.get("server", "").lower() and "cf-ray" not in h:
        return None

    # KEY 2, path A, the authoritative header. Cloudflare sets `cf-mitigated: block` only on a
    # real mitigation deny, so it stands alone (mirrors the challenge header path).
    if h.get("cf-mitigated", "").lower() == "block":
        return Verdict.BLOCKED, "cloudflare_block", 0.98, {"cf-mitigated": "block"}

    # KEY 2, path B, a WAF deny: status 403 AND the block-ONLY headline. Deliberately narrow:
    #   - NOT 429 (rate limit = transient, solvable by waiting, not a hard block),
    #   - NOT 5xx (origin-down errors 520-527 reuse the generic `cf-error-details` template),
    #   - 'cf-error-details' / 'Attention Required! | Cloudflare' are dropped: both are shared by
    #     challenge and origin-error pages, so they are not block-specific evidence.
    # 'Sorry, you have been blocked' is the stable block-only marker (a challenge says
    # 'Just a moment...'; an origin error says 'Web server is down').
    if status == 403 and "Sorry, you have been blocked" in body:
        return Verdict.BLOCKED, "cloudflare_block", 0.97, {"body": "Sorry, you have been blocked", "status": 403}

    return None


def _detect_datadome(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """DataDome mitigation: CHALLENGE (solvable CAPTCHA) or BLOCKED (hard deny)."""
    h = _lower_headers(headers)
    body = body or ""

    # KEY 1, vendor gate: a real DataDome cookie or proprietary header. A blog quoting the
    # markers lacks both.
    has_cookie = "datadome=" in h.get("set-cookie", "").lower()
    has_header = "x-datadome" in h or "x-dd-b" in h
    if not (has_cookie or has_header):
        return None

    # A DataDome mitigation is never a 2xx. On a 200 the cookie/header is just an allowed page,
    # and its site-wide CSP / preconnect may allow-list captcha-delivery.com, which is NOT a challenge.
    if status not in _DD_MITIGATION_STATUSES:
        return None

    low = body.lower()
    rt_match = _DD_RT.search(body)
    rt = rt_match.group(1).lower() if rt_match else None

    # Hard block (not solvable): rt:'b', or an explicit block headline.
    if rt == "b" or "you have been blocked" in low or "access denied" in low:
        return Verdict.BLOCKED, "datadome_block", 0.95, {"signal": "rt=b/block-headline", "status": status}
    # Solvable CAPTCHA: the captcha-delivery.com resource loaded via src=, or rt:'c'.
    if _DD_CAPTCHA_SRC.search(body) or rt == "c":
        return Verdict.CHALLENGE, "datadome", 0.97, {"signal": "captcha-delivery.com", "status": status}
    # Bare mitigation (Device Check / JSON deny): require the proprietary x-dd-b/x-datadome header
    # so a site's OWN 403 (cookie-only, ambiguous) is never mislabeled a DataDome block.
    if has_header:
        return Verdict.BLOCKED, "datadome_block", 0.9, {"signal": "datadome mitigation header", "status": status}
    return None


def _detect_akamai_block(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """Akamai (AkamaiGHost) WAF deny page. BLOCKED, via the two-key rule."""
    h = _lower_headers(headers)
    body = body or ""

    # KEY 1, vendor gate: the AkamaiGHost edge, or an Akamai Bot Manager cookie.
    server = h.get("server", "").lower()
    set_cookie = h.get("set-cookie", "").lower()
    if "akamaighost" not in server and not any(c in set_cookie for c in _AK_COOKIES):
        return None

    # The deny is non-2xx (Akamai denies at 403, and also 429/406/501). On a 2xx the Bot Manager
    # cookie is just an allowed protected page.
    if status is None or status < 400:
        return None

    # KEY 2, the bot-deny TEMPLATE, matched against DE-TAGGED text so an entity-encoded headline or
    # a Reference # split across inline tags still matches. Key on the deny-SPECIFIC phrase
    # "permission to access ... on this server": the generic "Access Denied" headline is shared by
    # 5xx edge/origin-error pages and geo/authz refusals, so it is not block-specific.
    parsed = HTMLParser(body)
    node = parsed.body or parsed.root
    # Empty separator so a Reference # split across inline tags re-joins contiguously.
    text = (node.text(separator="") if node is not None else "") or ""
    if "permission to access" in text.lower() and _AK_REFERENCE.search(text):
        return Verdict.BLOCKED, "akamai_block", 0.96, {"marker": "permission-to-access + Reference #", "status": status}
    return None


def _px_vendor_present(h: dict[str, str], set_cookie: str, body: str) -> bool:
    """PerimeterX vendor gate: a _px* cookie, an x-px header, or the sensor-JS assignment."""
    return (
        any(c in set_cookie for c in _PX_COOKIES)
        or any(k.startswith("x-px") for k in h)
        or bool(_PX_SENSOR.search(body))
    )


def _detect_perimeterx(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """PerimeterX / HUMAN 'Press & Hold' interstitial. CHALLENGE, via the two-key rule."""
    h = _lower_headers(headers)
    body = body or ""
    if not _px_vendor_present(h, h.get("set-cookie", "").lower(), body):
        return None
    # A PX interstitial is non-2xx (the _px cookie/sensor are on allowed 200s).
    if status not in _PX_CHALLENGE_STATUSES:
        return None
    # KEY 2, interstitial-specific: the px-captcha element, the captcha src, or verify-human copy.
    low = body.lower()
    if "px-captcha" in low or "_pxcaptcha" in low or _PX_CAPTCHA_SRC.search(body) or _PX_VERIFY.search(body):
        return Verdict.CHALLENGE, "perimeterx", 0.96, {"signal": "px interstitial", "status": status}
    return None


def _detect_perimeterx_block(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """PerimeterX hard deny, a DISTINCT page from the interstitial (challenge runs first). BLOCKED."""
    h = _lower_headers(headers)
    body = body or ""
    if not _px_vendor_present(h, h.get("set-cookie", "").lower(), body):
        return None
    if status != 403:
        return None
    low = body.lower()
    if any(phrase in low for phrase in _PX_DENY):
        return Verdict.BLOCKED, "perimeterx_block", 0.93, {"marker": "px deny"}
    return None


def _detect_kasada(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """Kasada proof-of-work interstitial. CHALLENGE: x-kpsdk header + non-2xx + the PoW script."""
    h = _lower_headers(headers)
    body = body or ""
    # KEY 1, vendor gate: an x-kpsdk-* response header.
    if not any(k.startswith("x-kpsdk") for k in h):
        return None
    # A Kasada mitigation is non-2xx; on a 200 the x-kpsdk-ct is just a cleared session.
    if status not in _KASADA_STATUSES:
        return None
    # KEY 2, the obfuscated proof-of-work script. Without it, a non-2xx on a cleared session (the
    # app's OWN 403/429) is not a Kasada challenge.
    if not _KASADA_POW.search(body):
        return None
    return Verdict.CHALLENGE, "kasada", 0.95, {"signal": "x-kpsdk + pow script", "status": status}


def _detect_captcha_interstitial(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """A full-page reCAPTCHA / Turnstile GATE, not a form that merely embeds a widget. CHALLENGE."""
    body = body or ""
    # KEY 1, a real reCAPTCHA or Turnstile widget on the page.
    if _RECAPTCHA.search(body):
        vendor = "recaptcha"
    elif _TURNSTILE.search(body):
        vendor = "turnstile"
    elif _HCAPTCHA.search(body):
        vendor = "hcaptcha"
    else:
        return None
    # KEY 2, a GATE, not an embed: content-light AND gate copy. A content-rich page (login/contact)
    # is excluded by the visible-text gate; a sparse demo is excluded by the missing gate copy.
    if _visible_text_len(body) >= _CAPTCHA_MAX_VISIBLE:
        return None
    low = body.lower()
    if not any(phrase in low for phrase in _CAPTCHA_GATE_COPY):
        return None
    # KEY 3, the captcha must be the page's PRIMARY interactive element, not a widget bolted onto a
    # data form. A content-light newsletter / comment / contact / signup form is sparse enough to clear
    # the visible-text gate and can carry gate-ish copy ('confirm you are human before submitting'),
    # yet it is a normal form, not a gate. A real gate collects no data: you solve it and proceed.
    if _has_data_entry_field(body):
        return None
    return Verdict.CHALLENGE, f"captcha_{vendor}", 0.9, {"vendor": vendor}


def _detect_incapsula(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """Imperva / Incapsula interstitial. CHALLENGE, via the two-key rule."""
    h = _lower_headers(headers)
    low = (body or "").lower()

    # KEY 1, vendor gate: an Incapsula cookie or X-Iinfo / X-CDN:Incapsula header.
    set_cookie = h.get("set-cookie", "").lower()
    vendor = (
        "incap_ses" in set_cookie or "visid_incap" in set_cookie
        or "x-iinfo" in h or "incapsula" in h.get("x-cdn", "").lower()
    )
    if not vendor:
        return None
    # KEY 2, the mitigation marker (the cookie/header are on allowed pages too).
    if any(marker in low for marker in _INCAP_MARKERS):
        return Verdict.CHALLENGE, "incapsula", 0.96, {"signal": "incapsula mitigation"}
    return None


def _detect_f5_block(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """F5 BIG-IP ASM (Advanced WAF) deny page. BLOCKED."""
    if status is None or status < 400:  # the F5 ASM reject is non-2xx
        return None
    body = body or ""
    # De-tag so phrases split across inline tags re-join (e.g. "support <b>ID</b> is:"), as the
    # Akamai detector does. Require the reject phrase AND a real "support ID is: <digits>" line, not
    # the bare 'support id' substring, which a help/docs/app-error page about F5 would also contain.
    parsed = HTMLParser(body)
    node = parsed.body or parsed.root
    text = (node.text(separator="") if node is not None else "") or ""
    if "the requested url was rejected" in text.lower() and _F5_SUPPORT_ID.search(text):
        return Verdict.BLOCKED, "f5_block", 0.95, {"marker": "f5 asm reject"}
    return None


def _anchor_is_hidden(node) -> bool:
    """True if the anchor (or any near ancestor, a hidden container) is hidden from humans.

    Raw-HTML only (no render): inline display:none / visibility / opacity / font-size:0 / 0|1px /
    clip / off-screen / transform-scale-0, aria-hidden, and the boolean `hidden` attribute. CSS-class
    hiding needs a render, out of scope.
    """
    current = node
    for _ in range(6):  # the anchor plus a few ancestors (a hidden wrapper div is the maze pattern)
        if current is None:
            break
        attrs = current.attributes
        if _HIDDEN_STYLE.search((attrs.get("style") or "").lower()):
            return True
        if (attrs.get("aria-hidden") or "").lower() == "true":
            return True
        if "hidden" in attrs:
            return True
        current = current.parent
    return False


def _is_trap_href(href: str) -> bool:
    """True only for a same-host, DEEP, internal path: the shape a maze lures crawlers to.

    Excludes #fragments, javascript:/mailto:/tel:, external/protocol-relative hosts (social-share,
    nav), and shallow single-segment utility routes (/login, /cart). A real maze fans out into
    fresh multi-segment paths (/maze/a1b2c3).
    """
    href = (href or "").strip()
    if not href.startswith("/") or href.startswith("//"):
        return False
    path = href.split("?", 1)[0].split("#", 1)[0]
    return len([seg for seg in path.split("/") if seg]) >= 2


def _detect_honeypot(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """A page exposing a cluster of INVISIBLE nofollow trap links into a same-host deep maze.

    Body-only signal: caught by the TRAP STRUCTURE, never the prose (a good decoy reads like a real
    article). The strongest signal (arriving via an invisible link on the parent) needs get()-level
    crawl context and is a follow-up.
    """
    body = body or ""
    if status is not None and status >= 400:
        return None  # a content trap is a 2xx; don't fire on error pages

    tree = HTMLParser(body)
    trap_links = 0
    for anchor in tree.css("a"):
        rel = (anchor.attributes.get("rel") or "").lower()
        if "nofollow" not in rel:
            continue
        if not _is_trap_href(anchor.attributes.get("href") or ""):
            continue
        if _anchor_is_hidden(anchor):
            trap_links += 1
    if trap_links >= _HONEYPOT_MIN_TRAP_LINKS:
        return Verdict.HONEYPOT, "trap_links", 0.85, {"hidden_nofollow_links": trap_links}
    return None


def _visible_text_len(body: str) -> int:
    """Length of server-rendered visible text, script/style/etc. stripped."""
    tree = HTMLParser(body)
    for tag in ("script", "style", "noscript", "template", "svg"):
        for node in tree.css(tag):
            node.decompose()
    body_node = tree.body
    return len((body_node.text(strip=True) if body_node else "") or "")


# A husk may hold only a short loading placeholder ("Loading...", "Please wait"), nothing more.
_HUSK_MAX_PLACEHOLDER = 20


def _is_empty_husk(node) -> bool:
    """True if a mount node holds no real content: no element children, and at most a short
    loading placeholder ('Loading...') of text, waiting for JS to fill it.

    A node holding a `<canvas>`/`<video>`/`<img>` (a map app, media player, image grid) has an
    element child, and a node holding a real sentence has substantive text. Both are rendered
    products, not husks.
    """
    if node is None:
        return False
    if len(node.text(strip=True) or "") > _HUSK_MAX_PLACEHOLDER:
        return False
    child = node.child
    while child is not None:
        if child.tag and child.tag != "-text":  # an element child = real content present
            return False
        child = child.next
    return True


def _detect_empty_shell(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """A 200 that is a JS app skeleton: no real content until JavaScript runs."""
    body = body or ""

    # A silent empty shell is a *successful-looking* response. Error pages are other verdicts.
    if status is None or status >= 400:
        return None
    # A tiny doc is a real small page (example.com), not a script-heavy app skeleton.
    if len(body) < _SHELL_MIN_BYTES:
        return None
    visible = _visible_text_len(body)
    if visible >= _SHELL_MAX_VISIBLE:
        return None

    # PRIMARY signal: an EMPTY-HUSK mount (empty of text and of element children). Low visible
    # text alone is not enough: a script-heavy page (e.g. nowsecure.nl) has no mount and is real.
    tree = HTMLParser(body)
    mount = None
    for mount_id in _MOUNT_IDS:
        if _is_empty_husk(tree.css_first(f"#{mount_id}")):
            mount = f"#{mount_id}"
            break
    if mount is None:
        # Any empty-husk CUSTOM ELEMENT (a hyphenated tag, required by the custom-elements spec;
        # standard HTML tags never contain a hyphen). Covers Angular's <app-root> and custom
        # bootstrap selectors like <cm-certemy>.
        for node in tree.css("*"):
            tag = node.tag or ""
            if "-" in tag and _is_empty_husk(node):
                mount = f"<{tag}>"
                break
    if mount is None:
        return None
    # A JS app skeleton always ships scripts to render itself; an empty mount with no script is not
    # a shell (e.g. a static placeholder). This keeps the lowered size floor safe.
    if "<script" not in body.lower():
        return None

    # A "JS-required" notice only CORROBORATES: it ships in <noscript> on fully server-rendered
    # pages too, so it can never stand alone.
    evidence: dict[str, Any] = {"empty_mount": mount, "visible_text": visible}
    confidence = 0.95
    if any(marker in body.lower() for marker in _JS_REQUIRED_MARKERS):
        evidence["js_required"] = True
        confidence = 0.97
    return Verdict.EMPTY_SHELL, "js_app_shell", confidence, evidence


def _login_evidence(signal: str, visible: int, intent: str | None) -> dict[str, Any]:
    ev: dict[str, Any] = {"signal": signal, "visible_text": visible}
    if intent:
        ev["intent"] = intent
    return ev


def _detect_login_wall(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """A 200 that is a sign-in gate (password or OAuth/SSO), not the data."""
    body = body or ""

    # The dangerous silent case: a 200 that renders a sign-in gate instead of content.
    if status != 200:
        return None
    low = body.lower()
    # Already authenticated (a logout affordance) -> not a sign-in gate.
    if "log out" in low or "logout" in low or "sign out" in low:
        return None

    # KEY 1, the gate must DOMINATE: a content-light page, or explicit gating intent. This is what
    # keeps an OAuth button (or a login box) in a content-rich article's chrome from firing.
    visible = _visible_text_len(body)
    intent = next((phrase for phrase in _LOGIN_INTENT if phrase in low), None)
    if visible >= _LOGIN_WALL_MAX_VISIBLE and intent is None:
        return None

    # Judge the MAIN content: strip the site-wide header/nav/footer chrome so a chrome login box
    # (or a chrome OAuth link) is not mistaken for the page's purpose.
    tree = HTMLParser(body)
    for chrome in ("header", "nav", "footer"):
        for node in tree.css(chrome):
            node.decompose()
    main = tree.body
    main_low = (main.text(separator=" ").lower() if main is not None else "")
    main_html = (main.html or "") if main is not None else ""

    # Account-management forms (reset / change-password / settings) are not a sign-in gate.
    if any(marker in main_low for marker in _ACCOUNT_MGMT_MARKERS):
        return None
    # A sign-in affordance must be present, so a stray password widget never qualifies.
    if not any(cue in main_low for cue in _SIGNIN_CUE):
        return None

    # KEY 2, a positive sign-in-gate signal in MAIN content.
    if tree.css_first('input[type="password"]') is not None:
        return Verdict.LOGIN_WALL, "login_wall", 0.9, _login_evidence("password form", visible, intent)
    if _AUTH_VENDOR_URLS.search(main_html) or _AUTH_FORM_ACTION.search(main_html) or _SSO_BUTTON.search(main_low):
        return Verdict.LOGIN_WALL, "login_wall", 0.8, _login_evidence("oauth/sso gate", visible, intent)
    return None


def _detect_soft_404(
    status: int | None, headers: dict[str, str] | None, body: str | None
) -> tuple[Verdict, str, float, dict[str, Any]] | None:
    """A 200 that is really a 'not found' / parked placeholder, by body markers."""
    body = body or ""
    if status != 200:
        return None

    # Judge the MAIN content: a not-found page can carry full site nav/chrome that inflates length.
    tree = HTMLParser(body)
    for tag in ("header", "nav", "footer", "script", "style", "noscript", "template", "svg"):
        for node in tree.css(tag):
            node.decompose()
    main = tree.body
    main_text = (main.text(separator=" ") if main is not None else "") or ""

    # A real article (e.g. one ABOUT 404 errors) is content-rich; a soft-404/parked main is short.
    if len(main_text.strip()) >= _SOFT_404_MAX_VISIBLE:
        return None

    # Match markers in the HEADLINE (title + h1/h2) only. A genuine soft-404/parked page LEADS with
    # the message; a real page (zero-result search, status dashboard, marketplace listing, geo notice)
    # only mentions it in passing in body text.
    title_node = tree.css_first("title")
    headline_parts = [title_node.text(strip=True)] if title_node is not None else []
    for tag in ("h1", "h2"):
        headline_parts.extend(node.text(separator=" ") for node in tree.css(tag))
    headline = " ".join(headline_parts).lower()

    parked = next((m for m in _PARKED_MARKERS if m in headline), None)
    if parked:
        return Verdict.SOFT_404, "parked_domain", 0.9, {"marker": parked}
    marker = next((m for m in _NOT_FOUND_MARKERS if m in headline), None)
    if marker:
        return Verdict.SOFT_404, "not_found", 0.85, {"marker": marker}
    return None


# Detectors run in order; the first positive verdict wins. Challenge before block so a
# challenge page (also 403) is never mislabeled as a hard block. Empty-shell is 2xx-only,
# so it cannot collide with the (non-2xx) challenge/block detectors.
_DETECTORS = (
    _detect_cloudflare_challenge,
    _detect_cloudflare_block,
    _detect_datadome,
    _detect_akamai_block,
    _detect_perimeterx,
    _detect_perimeterx_block,
    _detect_kasada,
    _detect_incapsula,
    _detect_f5_block,
    _detect_captcha_interstitial,
    _detect_honeypot,
    _detect_login_wall,
    _detect_soft_404,
    _detect_empty_shell,
)


def classify(
    *,
    status: int | None,
    headers: dict[str, str] | None,
    body: str | None,
) -> tuple[Verdict, str | None, float, dict[str, Any]]:
    """Return ``(verdict, cause, confidence, evidence)``.

    Runs each deterministic detector in turn; abstains (UNVERIFIED) if none fires.
    """
    for detector in _DETECTORS:
        hit = detector(status, headers, body)
        if hit is not None:
            return hit
    return _ABSTAIN
