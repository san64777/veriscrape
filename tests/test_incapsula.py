"""Imperva / Incapsula challenge detection.

Two-key: vendor gate is an Incapsula cookie (visid_incap_/incap_ses_) or X-Iinfo / X-CDN:Incapsula
header; the mitigation marker is block-ONLY text ('Request unsuccessful' / 'Incapsula incident ID')
or the iframe's 'incident_id=' param. NOT the bare '_Incapsula_Resource' substring, which is the
client-side sensor script Imperva injects into every protected page (allowed pages too).
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_incapsula_challenge_is_detected():
    verdict, cause, confidence, _ = classify_fixture("incapsula_challenge.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "incapsula"


def test_allowed_incapsula_page_is_not_flagged():
    # visid_incap cookie + X-CDN present, but no mitigation marker, so must not fire.
    verdict, *_ = classify_fixture("incapsula_allowed.json")
    assert verdict is not Verdict.CHALLENGE


def test_blog_quoting_incapsula_is_not_flagged():
    verdict, *_ = classify_fixture("incapsula_fp_blog.json")
    assert verdict is not Verdict.CHALLENGE


def test_allowed_incapsula_page_with_sensor_script_is_not_flagged():
    # The realistic allowed page: visid_incap cookie AND the '/_Incapsula_Resource?SWJIYLWA=...'
    # SENSOR script Imperva injects into EVERY protected page. The bare '_Incapsula_Resource'
    # substring must NOT be a standalone block marker (sensor-on-allowed-pages trap).
    verdict, *_ = classify_fixture("incapsula_allowed_sensor.json")
    assert verdict is not Verdict.CHALLENGE


def test_incapsula_block_served_at_200_is_detected():
    # Imperva sometimes returns the JS interstitial at 200; the block-only text still fires.
    d = json.loads((FIXTURES / "incapsula_challenge.json").read_text())
    verdict, cause, *_ = classify(status=200, headers=d["headers"], body=d["body"])
    assert verdict is Verdict.CHALLENGE
    assert cause == "incapsula"


def test_incapsula_iframe_only_block_is_detected():
    # A block page whose only block evidence is the iframe's 'incident_id=' param (no visible
    # 'Request unsuccessful' / 'Incapsula incident ID' phrase) is still caught.
    headers = {
        "X-Iinfo": "1-23456789-23456790 NNNN",
        "X-CDN": "Incapsula",
        "Set-Cookie": "incap_ses_123_1234567=GhIjKl==; path=/",
    }
    body = (
        "<html><body><iframe "
        "src=\"/_Incapsula_Resource?SWUDNSAI=31&incident_id=0061000130012345678-123\">"
        "</iframe></body></html>"
    )
    verdict, cause, *_ = classify(status=403, headers=headers, body=body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "incapsula"
