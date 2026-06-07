"""Kasada challenge detection: the obfuscated proof-of-work interstitial.

Two-key: vendor gate is an x-kpsdk-* response header; the mitigation signal is a non-2xx
status. A CLEARED Kasada session also carries x-kpsdk-ct on allowed 200s, so the header
alone is never the verdict; a bare 429 with no x-kpsdk header is not Kasada.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_kasada_interstitial_is_challenge():
    verdict, cause, confidence, _ = classify_fixture("kasada_challenge.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "kasada"


def test_cleared_kasada_200_is_not_flagged():
    # x-kpsdk-ct on an allowed 200 JSON response, so must not fire.
    verdict, *_ = classify_fixture("kasada_allowed.json")
    assert verdict is not Verdict.CHALLENGE


def test_generic_ratelimit_without_kpsdk_is_not_kasada():
    # A bare application 429 with no x-kpsdk header is not a Kasada challenge.
    verdict, *_ = classify_fixture("kasada_fp_ratelimit.json")
    assert verdict is not Verdict.CHALLENGE


def test_cleared_session_app_403_is_not_kasada():
    # A cleared session (x-kpsdk-ct present) hitting the app's OWN 403 (no proof-of-work script)
    # must NOT be called a Kasada challenge. The PoW body marker is the required second key.
    body = '{"error":"forbidden","message":"You do not have permission to access this resource."}'
    verdict, *_ = classify(
        status=403, headers={"x-kpsdk-ct": "06AbCdEf", "content-type": "application/json"}, body=body
    )
    assert verdict is not Verdict.CHALLENGE
