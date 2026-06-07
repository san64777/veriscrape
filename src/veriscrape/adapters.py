"""Drop-in adapters: add a trust verdict to the fetcher you already use.

`veriscrape.get()` is the drop-in for `requests.get`. But if you already have a Scrapy
spider, a Playwright page, or a raw `requests`/`httpx` response, you don't have to switch
fetchers, just classify what you already have:

    from veriscrape.adapters import from_requests, from_response

    resp = requests.get(url)
    record = from_requests(resp)          # -> FetchRecord with .verdict / .cause / .ok

    record = from_response(status, headers, body, url=url)   # any stack

Scrapy: add ``veriscrape.adapters.VeriscrapeMiddleware`` to ``DOWNLOADER_MIDDLEWARES`` and
read ``response.meta["veriscrape"]``.
"""

from __future__ import annotations

from . import FetchRecord, classify


def from_response(
    status: int | None,
    headers,
    body: str | None,
    *,
    url: str = "",
    tactic: str | None = None,
    elapsed_ms: float | None = None,
) -> FetchRecord:
    """Classify raw response parts from any stack into a FetchRecord."""
    headers = dict(headers or {})
    verdict, cause, confidence, evidence = classify(status=status, headers=headers, body=body or "")
    return FetchRecord(
        url=url, status=status, verdict=verdict, cause=cause, confidence=confidence,
        evidence=evidence, headers=headers, text=body, tactic=tactic, elapsed_ms=elapsed_ms,
    )


def from_requests(response) -> FetchRecord:
    """Classify a ``requests.Response`` (or any object with status_code/headers/text/url)."""
    return from_response(
        status=getattr(response, "status_code", None),
        headers=getattr(response, "headers", {}) or {},
        body=getattr(response, "text", "") or "",
        url=str(getattr(response, "url", "") or ""),
        tactic="requests",
    )


def _normalize_scrapy_headers(headers) -> dict[str, str]:
    """Best-effort: Scrapy headers are bytes-keyed and multi-valued. Flatten to str:str."""
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except Exception:
        return out
    for key, value in items:
        k = key.decode() if isinstance(key, bytes) else str(key)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else b""
        v = value.decode() if isinstance(value, bytes) else str(value)
        out[k] = v
    return out


class VeriscrapeMiddleware:
    """Scrapy downloader middleware: attaches a veriscrape verdict to every response.

    In ``settings.py``::

        DOWNLOADER_MIDDLEWARES = {"veriscrape.adapters.VeriscrapeMiddleware": 900}

    Then in a spider: ``response.meta["veriscrape"].verdict``.
    """

    def process_response(self, request, response, spider):
        record = from_response(
            status=getattr(response, "status", None),
            headers=_normalize_scrapy_headers(getattr(response, "headers", {})),
            body=getattr(response, "text", "") or "",
            url=str(getattr(response, "url", "") or ""),
            tactic="scrapy",
        )
        try:
            response.meta["veriscrape"] = record
        except Exception:
            pass  # never break the pipeline over a missing meta dict
        return response
