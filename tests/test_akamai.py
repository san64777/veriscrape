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
