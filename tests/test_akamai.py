"""Akamai (AkamaiGHost) block detection: the third anti-bot vendor.

Two-key: the vendor gate is `Server: AkamaiGHost` or an Akamai Bot Manager cookie
(_abck/bm_sz/...), and the block marker is the deny template ("Access Denied" +
the `Reference #<id>` tracking line). The blog fixture is a 403 that quotes those
exact markers but is served by nginx, so the vendor gate must carry the verdict.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_akamai_block_is_detected():
    verdict, cause, confidence, evidence = classify_fixture("akamai_block.json")
    assert verdict is Verdict.BLOCKED
    assert cause == "akamai_block"
    assert confidence >= 0.9


def test_allowed_akamai_page_is_not_flagged():
    # Carries Akamai Bot Manager cookies (vendor present) but no deny markers, so must not fire.
    verdict, *_ = classify_fixture("akamai_allowed.json")
    assert verdict is not Verdict.BLOCKED


def test_blog_quoting_akamai_markers_is_not_flagged():
    # A 403 that quotes "Access Denied" + a real-format Reference #, but served by nginx
    # (no AkamaiGHost, no Akamai cookie), so the vendor gate must reject it.
    verdict, *_ = classify_fixture("akamai_fp_blog.json")
    assert verdict is not Verdict.BLOCKED


# --- false-positive guards: the generic "Access Denied" + Reference # template is shared ---

def test_akamai_origin_error_5xx_is_not_blocked():
    # A 503 AkamaiGHost edge/origin-error page shares the Reference # template and can say
    # "Access Denied", but an origin being down is solvable by retry, not a hard bot block.
    body = (
        "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>"
        "An error occurred while processing your request.<P>"
        "Reference #97.4f2a1b3c.1718000000.0deadbef</P></BODY></HTML>"
    )
    verdict, *_ = classify(status=503, headers={"server": "AkamaiGHost"}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_akamai_geo_authz_403_is_not_blocked():
    # A geo/licensing AUTHZ refusal: 403 + "Access Denied" + Reference #, but the request was
    # understood and refused on authorization grounds, not fingerprinted as a bot.
    body = (
        "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>"
        "<p>This content is not available in your region due to licensing restrictions.</p>"
        "<p>Reference #18.1a2b3c4d.1718000000.0badc0de</p></body></html>"
    )
    verdict, *_ = classify(status=403, headers={"server": "AkamaiGHost", "set-cookie": "ak_bmsc=AAAA~"}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_akamai_fronted_help_404_is_not_blocked():
    # An Akamai-fronted help article that merely mentions the markers, at a non-2xx status.
    body = (
        '<article><h1>Troubleshooting: "Access Denied" errors</h1>'
        "<p>If you see an error like <code>Reference #18.dd5d2c17.1718000000.1a2b3c4d</code>, "
        "contact support. The page you requested could not be found.</p></article>"
    )
    verdict, *_ = classify(status=404, headers={"server": "AkamaiGHost", "set-cookie": "bm_sv=EEEE~"}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_akamai_block_with_encoded_or_split_markup_is_detected():
    # The headline is entity-encoded and the Reference # is split across <span>s, so de-tagging
    # the body must still recognize the genuine deny.
    body = (
        "<H1>&#65;ccess Denied</H1>You don<span>&#39;</span>t have permission to access "
        "&#34;http://protected.example/data&#34; on this server.<P>Reference #<span>18</span>."
        "<span>dd5d2c17</span>.1718000000.1a2b3c4d</P>"
    )
    verdict, cause, *_ = classify(status=403, headers={"server": "AkamaiGHost"}, body=body)
    assert verdict is Verdict.BLOCKED
    assert cause == "akamai_block"


def test_akamai_fronted_article_quoting_the_permission_phrase_is_not_blocked():
    # An Akamai-fronted, content-RICH KB article (404) that QUOTES the deny template verbatim:
    # "permission to access ... on this server" AND a real-format Reference #, in prose. Both
    # markers co-occur and both vendor keys are real, so the two-key rule alone does not save it;
    # the discriminator is that this is a long article, not the short bare deny template.
    filler_why = (
        "Automated clients without a warmed session, missing sensor cookies, or datacenter IP "
        "ranges are common triggers for this response. "
    )
    filler_fix = (
        "Retry through an approved egress, make sure the _abck and bm_sz cookies are present, and "
        "contact the site owner to request an allow-list for your integration. "
    )
    body = (
        '<article><h1>Fixing Akamai "Access Denied" (Reference #) errors on your API calls</h1>'
        "<p>Customers occasionally report that a request returns a page reading: "
        "<em>You don't have permission to access \"/v2/orders\" on this server.</em> followed by "
        "<code>Reference #18.1a2b3c4d.1718000000.0badc0de</code>. That is Akamai Bot Manager "
        "challenging the request, not your code.</p>"
        "<h2>Why this happens</h2><p>" + filler_why * 10 + "</p>"
        "<h2>How to resolve it</h2><p>" + filler_fix * 10 + "</p></article>"
    )
    verdict, *_ = classify(status=404, headers={"server": "AkamaiGHost", "set-cookie": "bm_sv=EEEE~"}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_akamai_deny_wrapped_in_site_chrome_is_blocked():
    # A GENUINE Akamai deny served through the origin's custom error template with full site chrome
    # (nav + footer), so whole-page text exceeds the content-light threshold but the MAIN deny is
    # still short. Must stay BLOCKED: the content-light gate measures MAIN content, not chrome.
    nav = "<header><nav>" + "Home Products Pricing Docs Support Blog Careers Contact " * 15 + "</nav></header>"
    footer = "<footer>" + "Terms Privacy Cookies Legal Sitemap Status Help " * 15 + "</footer>"
    deny = (
        "<h1>Access Denied</h1>"
        "<p>You don't have permission to access \"/data\" on this server.</p>"
        "<p>Reference #18.dd5d2c17.1718000000.1a2b3c4d</p>"
    )
    body = "<html><body>" + nav + deny + footer + "</body></html>"
    verdict, cause, *_ = classify(status=403, headers={"server": "AkamaiGHost"}, body=body)
    assert verdict is Verdict.BLOCKED
    assert cause == "akamai_block"


def test_akamai_fronted_article_with_content_in_chrome_tags_is_not_blocked():
    # A content-rich Akamai-fronted help page whose article text sits inside a semantic chrome tag
    # (<header>/<footer> are common wrappers). Stripping chrome must not collapse the page into a
    # "short deny": the markers, quoted in that prose, are not the page's MAIN deny content, so it
    # must not be flagged BLOCKED. Guards the inverse of the chrome-wrapped-deny case.
    para = (
        "If a request returns a page reading you don't have permission to access \"/x\" on this "
        "server with a Reference #18.dd5d2c17.1718000000.1a2b3c4d, it was challenged by Akamai. "
    )
    body = (
        '<html><body><header role="banner"><h1>Akamai error help</h1>'
        "<p>" + para * 12 + "</p></header></body></html>"
    )
    verdict, *_ = classify(status=404, headers={"server": "AkamaiGHost", "set-cookie": "bm_sv=EEEE~"}, body=body)
    assert verdict is not Verdict.BLOCKED
