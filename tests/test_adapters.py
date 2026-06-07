"""Drop-in adapter tests: classify responses from other stacks without importing them."""

from types import SimpleNamespace

from veriscrape import Verdict
from veriscrape.adapters import VeriscrapeMiddleware, from_requests, from_response

_SHELL = (
    "<html><head>"
    + "<script>/* pad */</script>" * 120
    + '</head><body><div id="app-mount"></div>'
    + "<noscript>You need to enable JavaScript to run this app.</noscript></body></html>"
)


def test_from_response_classifies_raw_parts():
    record = from_response(200, {}, _SHELL, url="https://x.test")
    assert record.verdict is Verdict.EMPTY_SHELL
    assert record.url == "https://x.test"


def test_from_requests_wraps_a_response_object():
    fake = SimpleNamespace(status_code=200, headers={}, text=_SHELL, url="https://x.test")
    record = from_requests(fake)
    assert record.verdict is Verdict.EMPTY_SHELL
    assert record.tactic == "requests"


def test_scrapy_middleware_attaches_verdict_and_returns_response():
    fake = SimpleNamespace(status=200, headers={}, text=_SHELL, url="https://x.test", meta={})
    mw = VeriscrapeMiddleware()
    out = mw.process_response(request=None, response=fake, spider=None)
    assert out is fake  # middleware passes the response through untouched
    assert fake.meta["veriscrape"].verdict is Verdict.EMPTY_SHELL
