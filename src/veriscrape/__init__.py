"""veriscrape: fetch, but it tells you the truth.

A verified-fetch primitive: every fetch returns the bytes *plus* a portable
trust verdict (OK / BLOCKED / CHALLENGE / HONEYPOT / SOFT_404 / LOGIN_WALL /
EMPTY_SHELL), so you know the moment your data is silently wrong, not three
days later through a downstream discrepancy.

    >>> import veriscrape
    >>> r = veriscrape.get("https://example.com")
    >>> r.verdict, r.confidence
"""

from __future__ import annotations

import time

from .classify import classify
from .record import FetchRecord, Verdict

__all__ = ["get", "FetchRecord", "Verdict", "classify", "__version__"]
__version__ = "0.0.1"

_DEFAULT_IMPERSONATE = "chrome"


def get(
    url: str,
    *,
    impersonate: str = _DEFAULT_IMPERSONATE,
    timeout: float = 30.0,
    **kwargs,
) -> FetchRecord:
    """Fetch ``url`` and return a :class:`FetchRecord` with a trust verdict.

    Drop-in for ``requests.get``, but the result tells you whether the 200 is
    real. Uses curl_cffi for browser-like TLS so you are not blocked on signal
    alone, then runs the deterministic classifier over the response.
    """
    # Imported lazily so that `import veriscrape` never requires the network stack.
    from curl_cffi import requests as cffi

    start = time.perf_counter()
    # impersonate is a free-form profile string at runtime; curl_cffi's stub narrows it to a Literal.
    resp = cffi.get(url, impersonate=impersonate, timeout=timeout, **kwargs)  # type: ignore[arg-type]
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    headers = {k: v for k, v in dict(resp.headers).items() if v is not None}
    body = resp.text
    verdict, cause, confidence, evidence = classify(
        status=resp.status_code, headers=headers, body=body
    )

    return FetchRecord(
        url=url,
        status=resp.status_code,
        verdict=verdict,
        cause=cause,
        tactic=f"curl_cffi:{impersonate}",
        confidence=confidence,
        evidence=evidence,
        headers=headers,
        text=body,
        elapsed_ms=elapsed_ms,
    )
