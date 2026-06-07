"""DataDome challenge detection: the second anti-bot vendor.

Two-key, like Cloudflare: the vendor gate is a real `datadome` cookie / DataDome
header (a blog quoting the markers won't have it), and the challenge marker is
the captcha-delivery.com host or the `var dd={` object. The cookie alone is on
allowed pages too, so it can never fire by itself.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_datadome_captcha_challenge_is_detected():
    verdict, cause, confidence, evidence = classify_fixture("datadome_challenge.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "datadome"
    assert confidence >= 0.9


def test_allowed_datadome_page_is_not_flagged():
    # Carries the datadome cookie (vendor present) but no challenge markers, so must not fire.
    verdict, *_ = classify_fixture("datadome_allowed.json")
    assert verdict is not Verdict.CHALLENGE


def test_blog_quoting_datadome_markers_is_not_flagged():
    # Mentions captcha-delivery.com / 'var dd' in prose but has no datadome cookie/header.
    verdict, *_ = classify_fixture("datadome_fp_blog.json")
    assert verdict is not Verdict.CHALLENGE


# --- false-positive guards: both keys present on an ALLOWED page ---

def test_csp_allowlist_on_allowed_page_is_not_flagged():
    # DataDome's docs tell sites to allow-list *.captcha-delivery.com in a site-wide CSP,
    # shipped on every allowed 200. Cookie + that mention must NOT read as a challenge.
    body = (
        '<head><meta http-equiv="Content-Security-Policy" '
        'content="frame-src *.captcha-delivery.com; script-src js.datadome.co">'
        "<title>Blue Widget</title></head><body><main><h1>Blue Widget</h1>"
        '<p>In stock.</p></main><script src="https://js.datadome.co/tags.js"></script></body>'
    )
    verdict, *_ = classify(status=200, headers={"set-cookie": "datadome=BByQw~; Path=/; Secure"}, body=body)
    assert verdict is Verdict.UNVERIFIED


def test_unrelated_var_dd_on_allowed_page_is_not_flagged():
    body = (
        "<body><main><h1>Upcoming Events</h1></main>"
        "<script>var dd = {monday:[], tuesday:[]};</script>"
        '<script src="https://js.datadome.co/tags.js"></script></body>'
    )
    verdict, *_ = classify(status=200, headers={"set-cookie": "datadome=DDaSy~"}, body=body)
    assert verdict is Verdict.UNVERIFIED


def test_apps_own_403_is_not_mislabeled_datadome():
    # An app's OWN 403 (datadome cookie present, but NO proprietary x-dd-b header and no DataDome
    # markers) must not be mislabeled a DataDome block: abstain.
    body = "<h1>403 Forbidden</h1><script>var dd={menuOpen:false}</script>"
    verdict, *_ = classify(status=403, headers={"set-cookie": "datadome=Frb~"}, body=body)
    assert verdict is Verdict.UNVERIFIED


# --- false-negative fixes: DataDome blocks are BLOCKED (not solvable), not CHALLENGE ---

def test_datadome_hard_block_is_blocked():
    body = "<h1>You have been blocked</h1><script>var dd={'rt':'b','host':'geo.captcha-delivery.com'}</script>"
    verdict, cause, *_ = classify(status=403, headers={"x-dd-b": "1", "set-cookie": "datadome=Blk~"}, body=body)
    assert verdict is Verdict.BLOCKED
    assert cause == "datadome_block"


def test_datadome_device_check_403_is_blocked():
    # A 403 with a fresh datadome cookie AND the proprietary x-dd-b header but empty body is a
    # DataDome mitigation, not allowed content.
    verdict, cause, *_ = classify(status=403, headers={"x-dd-b": "1", "set-cookie": "datadome=Dev~"}, body="")
    assert verdict is Verdict.BLOCKED
    assert cause == "datadome_block"


def test_datadome_json_deny_is_blocked():
    verdict, cause, *_ = classify(
        status=403,
        headers={"x-dd-b": "1", "content-type": "application/json", "set-cookie": "datadome=Jsn~"},
        body='{"detail":"Access denied","code":403}',
    )
    assert verdict is Verdict.BLOCKED
    assert cause == "datadome_block"
