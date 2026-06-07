"""CAPTCHA-interstitial detection: a full-page reCAPTCHA / Turnstile GATE.

The hard part is the false positive: the SAME widget sits on ordinary login / signup / contact
forms. Two-key: the widget (KEY1) PLUS a content-light, gate-shaped page with gate copy (KEY2).
A content-rich page that merely embeds a captcha, or a sparse demo without gate copy, must abstain.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_recaptcha_gate_is_challenge():
    verdict, cause, *_ = classify_fixture("recaptcha_gate.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "captcha_recaptcha"


def test_turnstile_gate_is_challenge():
    verdict, cause, *_ = classify_fixture("turnstile_gate.json")
    assert verdict is Verdict.CHALLENGE
    assert cause == "captcha_turnstile"


def test_recaptcha_demo_embed_is_not_a_gate():
    # Content-light page with the widget but NO gate copy = a demo/embed (like the live reCAPTCHA demo).
    verdict, cause, *_ = classify_fixture("recaptcha_demo_embed.json")
    assert cause != "captcha_recaptcha"
    assert verdict is not Verdict.CHALLENGE


def test_login_form_with_recaptcha_is_not_a_captcha_gate():
    # A content-rich login page that embeds reCAPTCHA, so the captcha detector must abstain (it may be
    # a LOGIN_WALL via that detector, but it is NOT a captcha CHALLENGE).
    _, cause, *_ = classify_fixture("recaptcha_login.json")
    assert cause != "captcha_recaptcha"


_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


def _classify(body):
    return classify(status=200, headers=_HEADERS, body=body)


def test_sparse_newsletter_form_with_gate_copy_is_not_a_captcha_gate():
    # A content-light newsletter signup (clears the visible-text gate) that embeds reCAPTCHA and
    # carries gate-ish copy. It COLLECTS data (an email field) so it is a normal form, not a gate.
    body = (
        '<!doctype html><html><head><title>Subscribe</title>'
        '<script src="https://www.google.com/recaptcha/api.js"></script></head>'
        '<body><h2>Join our newsletter</h2><form action="/subscribe" method="post">'
        '<label>Email</label><input type="email" name="email">'
        '<p>Confirm you are human, then hit subscribe.</p>'
        '<div class="g-recaptcha" data-sitekey="6LdA"></div>'
        '<button type="submit">Subscribe</button></form></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert cause != "captcha_recaptcha"
    assert verdict is not Verdict.CHALLENGE


def test_sparse_comment_form_with_gate_copy_is_not_a_captcha_gate():
    # A blog comment box (textarea + name) that embeds reCAPTCHA and says 'verify you are human
    # before posting'. The textarea marks it a real form, not a gate.
    body = (
        '<!doctype html><html><head><title>Comment</title>'
        '<script src="https://www.google.com/recaptcha/api.js"></script></head>'
        '<body><h3>Leave a reply</h3><form action="/comment" method="post">'
        '<textarea name="comment"></textarea><label>Name</label><input name="name">'
        '<p>Please verify you are human before posting your comment.</p>'
        '<div class="g-recaptcha" data-sitekey="6LdB"></div>'
        '<button>Post comment</button></form></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert cause != "captcha_recaptcha"
    assert verdict is not Verdict.CHALLENGE


def test_sparse_signup_form_with_turnstile_and_gate_copy_is_not_a_gate():
    # A signup form (email + password) embedding Turnstile with 'verify to continue' copy.
    body = (
        '<!doctype html><html><head><title>Create account</title>'
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></head>'
        '<body><h2>Sign up</h2><form action="/register" method="post">'
        '<input name="email"><input type="password" name="password">'
        '<p>Verify to continue and create your account.</p>'
        '<div class="cf-turnstile" data-sitekey="0x4A"></div>'
        '<button>Create account</button></form></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert cause != "captcha_turnstile"
    assert verdict is not Verdict.CHALLENGE


def test_hcaptcha_gate_is_challenge():
    # hCaptcha is the third common embeddable captcha, and a full-page hCaptcha gate is in scope.
    body = (
        '<!doctype html><html><head><title>Security Check</title>'
        '<script src="https://hcaptcha.com/1/api.js" async defer></script></head>'
        '<body><h1>Verify you are human</h1><p>Complete the CAPTCHA to continue.</p>'
        '<div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "captcha_hcaptcha"


def test_hcaptcha_signup_form_is_not_a_gate():
    # hCaptcha on a data-entry signup form is a normal form, not a gate (KEY3 must apply to hCaptcha too).
    body = (
        '<!doctype html><html><head><script src="https://hcaptcha.com/1/api.js"></script></head>'
        '<body><h2>Sign up</h2><form><input type="email"><p>Confirm you are human.</p>'
        '<div class="h-captcha"></div><button>Register</button></form></body></html>'
    )
    _, cause, *_ = _classify(body)
    assert cause != "captcha_hcaptcha"


def test_gate_with_not_a_robot_copy_is_challenge():
    # 'Verify you are not a robot' / 'verify THAT you are human' are common gate phrasings.
    body = (
        '<!doctype html><html><head><title>Check</title>'
        '<script src="https://www.google.com/recaptcha/api.js"></script></head>'
        '<body><h1>Verify you are not a robot</h1>'
        '<div class="g-recaptcha" data-sitekey="6LdX"></div></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "captcha_recaptcha"


def test_real_gate_wrapped_in_form_with_hidden_and_submit_still_fires():
    # A genuine gate often wraps the widget in a <form> with a CSRF hidden field and a submit button.
    # Hidden/submit inputs are NOT data-entry, so the gate must still classify as CHALLENGE.
    body = (
        '<!doctype html><html><head><title>Security Check</title>'
        '<script src="https://www.google.com/recaptcha/api.js"></script></head>'
        '<body><h1>Verify you are human</h1><p>Complete the CAPTCHA to continue.</p>'
        '<form action="/verify" method="post">'
        '<input type="hidden" name="csrf" value="abc">'
        '<div class="g-recaptcha" data-sitekey="6LdX"></div>'
        '<input type="submit" value="Continue"></form></body></html>'
    )
    verdict, cause, *_ = _classify(body)
    assert verdict is Verdict.CHALLENGE
    assert cause == "captcha_recaptcha"
