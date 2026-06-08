"""Positive OK detection: the affirmative verdict that completes the spine.

OK is the inverse of EMPTY_SHELL and runs LAST: a 200 with a real document (a <title>) and
substantial server-rendered visible text. Every negative verdict wins first, and anything short or
ambiguous stays UNVERIFIED (abstain over guess), so OK is never a guess on thin evidence.
"""

from veriscrape import Verdict, classify
from veriscrape.adapters import from_response


def _article(paragraphs: int) -> str:
    para = (
        "<p>veriscrape returns a deterministic trust verdict alongside the bytes, so a silent failure "
        "is caught at fetch time instead of days later in a downstream report.</p>"
    )
    return (
        "<html><head><title>A real article</title></head><body><main>"
        "<h1>A real heading</h1>" + para * paragraphs + "</main></body></html>"
    )


def test_content_rich_200_is_ok():
    verdict, cause, confidence, _ = classify(status=200, headers={"content-type": "text/html"}, body=_article(8))
    assert verdict is Verdict.OK
    assert cause == "content_ok"
    assert confidence >= 0.8


def test_ok_verdict_makes_record_ok_true():
    r = from_response(200, {"content-type": "text/html"}, _article(8), url="https://example.test/article")
    assert r.verdict is Verdict.OK
    assert r.ok is True


def test_tiny_stub_page_abstains_rather_than_blessing_ok():
    # A complete but tiny page (example.com shape, ~80 visible chars) lacks enough affirmative
    # evidence to bless. Abstain (UNVERIFIED) rather than guess OK.
    body = (
        "<html><head><title>Example Domain</title></head><body>"
        "<h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p>"
        '<p><a href="https://www.iana.org/domains/example">More information</a></p></body></html>'
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.UNVERIFIED


def test_200_without_a_title_is_not_ok():
    # Substantial text but no <title>: not a complete document, so abstain.
    body = "<html><body><main>" + ("<p>Plenty of real looking body text here, repeated for length. </p>" * 20) + "</main></body></html>"
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.UNVERIFIED


def test_non_200_with_content_is_not_ok():
    # OK is a 200-only affirmation; a 404 with a body is not origin content.
    verdict, *_ = classify(status=404, headers={}, body=_article(8))
    assert verdict is Verdict.UNVERIFIED


def test_a_negative_verdict_still_wins_over_ok():
    # A content-bearing page that is really a sign-in gate must be LOGIN_WALL, not OK: the negative
    # detector runs before the OK detector.
    body = (
        "<html><head><title>Sign in</title></head><body><main>"
        "<h1>Sign in to continue</h1><p>Please sign in to continue reading this content.</p>"
        '<form action="/login"><input type="password" name="pw"></form>'
        "</main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.LOGIN_WALL


# --- the dangerous class: bad-AND-long pages that fall through the content-light negative
# detectors. Length is NOT evidence of content, so OK must disqualify these by headline/gate phrase.

def test_content_rich_soft_404_is_not_ok():
    # A 200 "page not found" padded with a long "popular articles" list, so its main content exceeds
    # the soft-404 length gate and soft-404 abstains. OK must not then bless it.
    links = "".join(f'<li><a href="/p/{i}">Popular article number {i} about widgets and gadgets</a></li>' for i in range(40))
    body = (
        "<html><head><title>Page not found - Acme Blog</title></head><body><main>"
        "<h1>Page not found</h1><p>The page you requested could not be found. Try one of these:</p>"
        "<ul>" + links + "</ul></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_soft_paywall_teaser_is_not_ok():
    # A long article teaser behind a soft paywall (no password, no SSO, no "sign in" cue, so the
    # login-wall detector misses it). The unresolved subscribe gate must keep it out of OK.
    teaser = "<p>" + ("Markets rallied today as investors weighed the latest economic signals. " * 20) + "</p>"
    body = (
        "<html><head><title>Big Market Story</title></head><body><main>"
        "<h1>Big Market Story</h1>" + teaser +
        "<section><h2>Subscribe to keep reading</h2><p>You have reached your free article limit.</p>"
        "<button>Subscribe</button></section></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_account_suspended_page_is_not_ok():
    body = (
        "<html><head><title>Account Suspended</title></head><body><main><h1>Account Suspended</h1>"
        "<p>" + ("This account has been suspended. Please contact support for assistance. " * 20) + "</p></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_generic_error_served_as_200_is_not_ok():
    body = (
        "<html><head><title>Something went wrong</title></head><body><main><h1>Something went wrong</h1>"
        "<p>" + ("An unexpected error occurred while processing your request. Please try again later. " * 18) + "</p></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_consent_cookie_wall_is_not_ok():
    body = (
        "<html><head><title>We value your privacy</title></head><body><main><h1>We value your privacy</h1>"
        "<p>" + ("We and our partners store and access information on your device using cookies. " * 22) + "</p>"
        "<button>Accept all</button><button>Reject all</button></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_geo_block_with_reason_in_body_is_not_ok():
    # A geo-block served as 200: benign headline, the damning reason is in body prose. The body-level
    # disqualifier must catch it (headline-only matching would bless it).
    body = (
        "<html><head><title>Video unavailable</title></head><body><main><h1>Video unavailable</h1>"
        "<p>" + ("We are sorry, but this video is not available in your country due to rights restrictions. " * 12) + "</p></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_maintenance_page_served_as_200_is_not_ok():
    body = (
        "<html><head><title>Acme</title></head><body><main><h1>Scheduled maintenance</h1>"
        "<p>" + ("We will be back soon. The site is temporarily offline for scheduled maintenance. " * 14) + "</p></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_age_gate_served_as_200_is_not_ok():
    body = (
        "<html><head><title>Welcome</title></head><body><main><h1>Welcome</h1>"
        "<p>" + ("Are you over 18? You must confirm your age to enter this site and view the content. " * 12) + "</p>"
        "<button>Yes</button><button>No</button></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK


def test_real_privacy_policy_page_is_still_ok():
    # A genuine Privacy Policy document is real content, not a consent wall: the "Privacy Policy"
    # headline does not match the consent-wall disqualifier, so it must stay OK (guards not too broad).
    body = (
        "<html><head><title>Privacy Policy</title></head><body><main><h1>Privacy Policy</h1>"
        + ("<p>This policy explains what data we collect, how we use it, and the choices you have. </p>" * 12)
        + "</main></body></html>"
    )
    verdict, cause, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.OK
    assert cause == "content_ok"


def test_metered_paywall_free_preview_is_not_ok():
    # A content-rich teaser behind a metered paywall ("you have read your free preview"). The FULL
    # article is not present, so OK must not bless the teaser as real content.
    teaser = "<p>" + ("The mayor outlined a sweeping plan for the waterfront district today. " * 18) + "</p>"
    body = (
        "<html><head><title>Waterfront Plan Unveiled</title></head><body><main>"
        "<h1>Waterfront Plan Unveiled</h1>" + teaser +
        "<section><p>You have read your free preview of this article. "
        '<a href="https://accounts.google.com/o/oauth2/v2/auth">Continue with Google</a> to read the rest.</p>'
        "</section></main></body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.OK
