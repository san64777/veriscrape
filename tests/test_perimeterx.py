"""PerimeterX / HUMAN challenge detection: the 'Press & Hold' interstitial.

Two-key: vendor gate is a real _px* cookie / x-px header; the challenge marker is the
Press-&-Hold copy or px-captcha. The _px* cookie AND the sensor JS (_pxAppId,
client.perimeterx.net) are on allowed pages too, so neither can fire on its own.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_perimeterx_press_and_hold_is_challenge():
    verdict, cause, confidence, _ = classify_fixture("perimeterx_challenge.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "perimeterx"


def test_allowed_perimeterx_page_is_not_flagged():
    # Has the _pxvid cookie AND the sensor JS, but no Press-&-Hold challenge markers.
    verdict, *_ = classify_fixture("perimeterx_allowed.json")
    assert verdict is not Verdict.CHALLENGE


def test_blog_quoting_perimeterx_is_not_flagged():
    verdict, *_ = classify_fixture("perimeterx_fp_blog.json")
    assert verdict is not Verdict.CHALLENGE


# --- false-positive guards (PX-protected ALLOWED 200 pages) ---

def test_press_and_hold_ui_on_allowed_page_is_not_challenge():
    # 'Press & Hold' is generic UI copy (record button); the non-2xx gate must clear a 200 page.
    body = (
        "<html><body><main><h1>Voice Notes</h1><button>Press &amp; Hold to record</button></main>"
        "<script>window._pxAppId='PX';</script></body></html>"
    )
    verdict, *_ = classify(status=200, headers={"set-cookie": "_px3=a1b2c3; Path=/"}, body=body)
    assert verdict is not Verdict.CHALLENGE


def test_captcha_preconnect_on_allowed_page_is_not_challenge():
    body = (
        "<html><head><link rel='preconnect' href='https://captcha.px-cdn.net'></head>"
        "<body><main><h1>Sneaker XR-1</h1></main><div id='px-captcha' style='display:none'></div>"
        "<script src='https://client.perimeterx.net/PX/main.min.js'></script></body></html>"
    )
    verdict, *_ = classify(status=200, headers={"set-cookie": "_px3=zzz"}, body=body)
    assert verdict is not Verdict.CHALLENGE


# --- false-negative fixes ---

def test_perimeterx_hard_block_is_blocked():
    # A PX deny page (403, _px cookie, deny copy, NO interstitial markers) is BLOCKED, not CHALLENGE.
    body = (
        "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>"
        "<p>You don't have permission to access this resource.</p>"
        "<script>window._pxAppId='PX';</script></body></html>"
    )
    verdict, cause, *_ = classify(status=403, headers={"set-cookie": "_px3=deadbeef"}, body=body)
    assert verdict is Verdict.BLOCKED
    assert cause == "perimeterx_block"


def test_human_rebrand_copy_is_challenge():
    # Post-rebrand HUMAN copy 'Verify you are human' (no 'a').
    body = "<html><body><h1>Verify you are human</h1><div id='human-challenge'></div></body></html>"
    verdict, cause, *_ = classify(status=403, headers={"set-cookie": "_px3=abc"}, body=body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "perimeterx"


def test_request_only_px_cookie_challenge_is_detected():
    # No Set-Cookie on the response; vendor identified by the sensor JS, challenge by px-captcha.
    body = (
        "<html><body><div id='px-captcha'></div><h1>Please verify you are a human</h1>"
        "<script>window._pxAppId='PXabc';</script></body></html>"
    )
    verdict, cause, *_ = classify(status=403, headers={"content-type": "text/html"}, body=body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "perimeterx"
