"""Foundational tests for the FetchRecord spine and the classifier contract.

These run with no network: the detection rules (built next) are pure functions
over captured fixtures, which is the whole point of the deterministic design.
"""

from veriscrape import FetchRecord, Verdict, classify


def test_default_verdict_is_unverified():
    r = FetchRecord(url="https://example.com")
    assert r.verdict is Verdict.UNVERIFIED
    assert not r.ok  # abstaining is never "ok"


def test_ok_property_is_true_only_for_ok_verdict():
    r = FetchRecord(url="https://example.com", status=200, verdict=Verdict.OK, confidence=0.95)
    assert r.ok

    blocked = FetchRecord(url="https://example.com", status=200, verdict=Verdict.BLOCKED)
    assert not blocked.ok  # a 200 that is really a block is NOT ok


def test_record_is_portable_json():
    r = FetchRecord(
        url="https://example.com",
        status=200,
        verdict=Verdict.BLOCKED,
        cause="cloudflare_challenge",
        confidence=0.9,
        evidence={"marker": "window._cf_chl_opt"},
    )
    restored = FetchRecord.model_validate_json(r.model_dump_json())
    assert restored.verdict is Verdict.BLOCKED
    assert restored.cause == "cloudflare_challenge"
    assert restored.evidence["marker"] == "window._cf_chl_opt"


def test_classifier_abstains_by_default():
    verdict, cause, confidence, evidence = classify(status=200, headers={}, body="<html></html>")
    assert verdict is Verdict.UNVERIFIED
    assert confidence == 0.0
    assert cause is None
