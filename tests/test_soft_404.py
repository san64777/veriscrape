"""Soft-404 detection: a 200 that is really a "not found" / parked placeholder.

Body-marker path only (the network "control request" trick is a separate get()-layer
strategy). The discriminator: a not-found / parked marker in content-LIGHT MAIN content
(site chrome stripped), so a real article ABOUT 404 errors does not fire.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def _verdict(body, status=200):
    return classify(status=status, headers={}, body=body)[0]


def test_not_found_served_as_200_is_soft_404():
    verdict, cause, *_ = classify_fixture("soft_404_not_found.json")
    assert verdict is Verdict.SOFT_404
    assert cause == "not_found"


def test_parked_domain_is_soft_404():
    verdict, cause, *_ = classify_fixture("soft_404_parked.json")
    assert verdict is Verdict.SOFT_404
    assert cause == "parked_domain"


def test_article_about_404_errors_is_not_soft_404():
    # A real, content-rich article that explains "page not found" errors must NOT be flagged.
    body = (
        "<html><head><title>How to fix Page Not Found errors</title></head><body><main>"
        "<h1>How to fix Page Not Found errors on your site</h1>"
        + (
            "<p>When a visitor hits a page not found error your server should return a real 404 "
            "status code. Here is how to configure that correctly across common web frameworks and "
            "why it matters for SEO, crawl budget, and analytics hygiene over time. </p>" * 12
        )
        + "</main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404


def test_real_content_page_is_not_soft_404():
    verdict, *_ = classify_fixture("control_hn.json")
    assert verdict is not Verdict.SOFT_404


def test_short_real_page_without_markers_is_not_soft_404():
    body = (
        "<html><head><title>Contact</title></head><body><main><h1>Contact us</h1>"
        "<p>Email hello@example.com or call 555-0100. We reply within one business day.</p>"
        "</main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404


# --- false-positive guards: the marker must be the page's HEADLINE, not a passing body mention ---

def test_not_foundation_substring_is_not_soft_404():
    # 'not found' must not match inside the unrelated word 'not foundation'.
    body = (
        "<html><head><title>Donate</title></head><body><main><h1>Donate</h1>"
        "<p>We are a charity, not foundation-funded. Your gift helps directly.</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404


def test_zero_result_search_is_not_soft_404():
    # A real, functional search endpoint that returned an empty set IS the requested data.
    body = (
        "<html><head><title>Search results</title></head><body><main><h1>Catalog search</h1>"
        '<p>Your search for "xyzzy" returned no results. The items you searched for were not '
        "found in our catalog.</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404


def test_domain_marketplace_listing_is_not_soft_404():
    # A real for-sale LISTING (h1 = domain name) is content the scraper wants, not a parked stub.
    body = (
        "<html><head><title>get.example for sale</title></head><body><main><h1>get.example</h1>"
        "<p>This domain is for sale by the owner. Current price: USD 12,000. "
        "Buy this domain securely through escrow.</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404


def test_status_dashboard_rendering_404_is_not_soft_404():
    body = (
        "<html><head><title>API Status</title></head><body><main><h1>API Status</h1>"
        '<div class="tile">Endpoint /v2/users: 404 Not Found rate is 0.2% over the last hour.</div>'
        '<div class="tile">All systems operational.</div></main></body></html>'
    )
    assert _verdict(body) is not Verdict.SOFT_404


def test_geo_restricted_page_not_available_is_not_soft_404():
    body = (
        "<html><head><title>Action movies</title></head><body><main><h1>Action movies - filtered</h1>"
        "<p>This page not available in your region. Some titles are restricted by licensing.</p>"
        "</main></body></html>"
    )
    assert _verdict(body) is not Verdict.SOFT_404
