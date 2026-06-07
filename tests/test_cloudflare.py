"""Cloudflare challenge detection, built test-first against real + faithful fixtures.

The hard part is the false positive: an *allowed* Cloudflare-fronted page also
carries the vendor headers and even a `cdn-cgi/challenge-platform` reference.
The two-key rule (vendor gate AND a challenge-specific marker) is what separates
a real challenge from an allowed page, and the negative fixtures here are live
captures, so this guards against the naive substring match.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_cloudflare_managed_challenge_is_detected():
    verdict, cause, confidence, evidence = classify_fixture("cloudflare_challenge.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "cloudflare_challenge"
    assert confidence >= 0.9


def test_allowed_cloudflare_page_with_challenge_platform_is_not_flagged():
    # Live capture: contains 'cdn-cgi/challenge-platform' but NO window._cf_chl_opt
    # and NO cf-mitigated header. The two-key rule must NOT call this a challenge.
    verdict, *_ = classify_fixture("cloudflare_allowed_nowsecure.json")
    assert verdict is not Verdict.CHALLENGE


def test_plain_control_page_is_not_flagged():
    verdict, *_ = classify_fixture("control_example.json")
    assert verdict is not Verdict.CHALLENGE


def test_blog_quoting_cf_chl_opt_token_is_not_flagged():
    # Allowed article behind Cloudflare that merely mentions the token in prose (status 200).
    # The bare-substring rule wrongly flagged this, the most common real false positive.
    verdict, *_ = classify_fixture("cloudflare_fp_blog_mention.json")
    assert verdict is not Verdict.CHALLENGE


def test_archived_challenge_snapshot_is_not_flagged():
    # A 200 snapshot embedding a real challenge assignment; the non-2xx status gate must save it.
    verdict, *_ = classify_fixture("cloudflare_fp_archived_snapshot.json")
    assert verdict is not Verdict.CHALLENGE


def test_cf_mitigated_header_alone_is_a_challenge():
    # The cf-mitigated:challenge header is authoritative (Cloudflare sets it only on a challenge),
    # so it stands as a challenge even with no body markers.
    verdict, cause, *_ = classify(
        status=403, headers={"server": "cloudflare", "cf-mitigated": "challenge"}, body=""
    )
    assert verdict is Verdict.CHALLENGE
    assert cause == "cloudflare_challenge"


def test_cloudflare_hard_block_is_detected():
    # A WAF hard block ("Sorry, you have been blocked", 403) is BLOCKED, not solvable by waiting.
    verdict, cause, confidence, evidence = classify_fixture("cloudflare_block.json")
    assert verdict is Verdict.BLOCKED
    assert cause == "cloudflare_block"
    assert confidence >= 0.9


def test_blog_about_cf_blocks_is_not_flagged_blocked():
    # Allowed 200 article that quotes the block-page markers; the status gate must save it.
    verdict, *_ = classify_fixture("cloudflare_fp_block_blog.json")
    assert verdict is not Verdict.BLOCKED


def test_challenge_is_not_misread_as_block():
    # The challenge page must stay CHALLENGE (solvable), never get stolen by the block detector.
    verdict, *_ = classify_fixture("cloudflare_challenge.json")
    assert verdict is Verdict.CHALLENGE


def test_origin_down_5xx_is_not_blocked():
    # A 522/503 "origin is down" page shares the cf-error-details template but is NOT a bot block.
    verdict, *_ = classify_fixture("cloudflare_origin_error_522.json")
    assert verdict is not Verdict.BLOCKED


def test_rate_limit_is_not_a_hard_block():
    # A 429 rate limit is transient (solvable by waiting), the opposite of a hard block.
    verdict, *_ = classify_fixture("cloudflare_ratelimit_1015.json")
    assert verdict is not Verdict.BLOCKED


def test_modern_block_template_is_detected():
    # The 2023+ block template drops cf-error-details; key on the block-only headline instead.
    verdict, cause, *_ = classify_fixture("cloudflare_block_modern.json")
    assert verdict is Verdict.BLOCKED
    assert cause == "cloudflare_block"


def test_cf_mitigated_block_header_alone_is_blocked():
    # cf-mitigated:block is authoritative (Cloudflare sets it only on a real mitigation deny).
    verdict, cause, *_ = classify(
        status=403, headers={"server": "cloudflare", "cf-mitigated": "block"}, body=""
    )
    assert verdict is Verdict.BLOCKED
    assert cause == "cloudflare_block"
