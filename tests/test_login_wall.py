"""Login-wall detection: a 200 that is a sign-in gate, not the data.

Login walls are genuinely ambiguous, so the rule is conservative:
  - the gate must DOMINATE (content-light page, or explicit gating intent),
  - the auth signal must be in MAIN content (a header/nav login box is not a wall),
  - account-management forms (reset / register / change-password / settings) are excluded,
  - a sign-in affordance is required (a stray password widget is not a wall),
  - and a password-free path catches modern OAuth/SSO logins (no password field at all).
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

_LONG = "Our team has spent years refining this product and the results speak for themselves. " * 40


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def _verdict(body, status=200, headers=None):
    return classify(status=status, headers=headers or {}, body=body)[0]


# --- positives ---

def test_login_form_page_is_a_wall():
    verdict, cause, *_ = classify_fixture("login_wall_hn.json")
    assert verdict is Verdict.LOGIN_WALL
    assert cause == "login_wall"


def test_soft_gate_with_intent_phrase_is_a_wall():
    body = (
        "<html><head><title>Members</title></head><body><main>"
        f"<h2>Sign in to continue</h2><p>{_LONG}</p>"
        '<form action="/login"><input type="password" name="pw"></form></main></body></html>'
    )
    assert _verdict(body) is Verdict.LOGIN_WALL


def test_oauth_only_login_is_a_wall():
    # Modern OAuth/SSO gate: a sign-in heading + provider redirects, NO password field.
    body = (
        "<html><head><title>Sign in - Acme</title></head><body><main>"
        "<h1>Sign in to your account</h1>"
        '<a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=123">Sign in with Google</a>'
        '<a href="https://appleid.apple.com/auth/authorize">Sign in with Apple</a>'
        "</main></body></html>"
    )
    assert _verdict(body) is Verdict.LOGIN_WALL


# --- false-positive guards ---

def test_long_article_with_header_login_box_is_not_a_wall():
    body = (
        "<html><head><title>The Great Article</title></head><body>"
        '<header><form action="/login"><input type="password" name="pw"></form></header>'
        f"<main><h1>The Great Article</h1><p>{_LONG}</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_short_landing_page_with_header_login_box_is_not_a_wall():
    # Content-light, but the password lives in the site-wide header chrome, not a wall.
    body = (
        "<html><head><title>Acme</title></head><body>"
        '<header><nav><form action="/login"><input type="password"></form></nav></header>'
        "<main><h1>Acme makes invoicing simple.</h1><p>Start in seconds. No credit card.</p></main>"
        "</body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_password_reset_page_is_not_a_wall():
    body = (
        "<html><head><title>Reset password</title></head><body><main><h1>Reset your password</h1>"
        '<form action="/reset"><input type="password" name="new_password">'
        '<input type="password" name="confirm_password"></form></main></body></html>'
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_change_password_settings_page_is_not_a_wall():
    body = (
        "<html><body><nav>Dashboard | Settings | Logout</nav><main><h1>Security settings</h1>"
        '<form action="/settings/password"><input type="password" name="current">'
        '<input type="password" name="new"></form></main></body></html>'
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_stray_password_widget_is_not_a_wall():
    # A content-light utility page with a password input but no sign-in affordance.
    body = (
        "<html><head><title>Password strength tester</title></head><body><main>"
        "<h1>Test your password strength</h1><input type=\"password\"></main></body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_oauth_button_in_content_rich_article_is_not_a_wall():
    body = (
        "<html><head><title>Great Article</title></head><body>"
        '<header><a href="https://accounts.google.com/o/oauth2/v2/auth">Sign in with Google</a></header>'
        f"<main><h1>Great Article</h1><p>{_LONG}</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_content_page_without_auth_is_not_a_wall():
    verdict, *_ = classify_fixture("control_hn.json")
    assert verdict is not Verdict.LOGIN_WALL


def test_content_rich_homepage_with_sso_link_and_weak_intent_is_not_a_wall():
    # The real-world G2 homepage shape (a confirmed false positive): thousands of visible chars of
    # genuine content, an SSO link, and a weak "log in to view more" affordance. The weak SSO signal
    # must NOT flag a content-rich page as a login wall; it can only carry a content-light gate where
    # the gate dominates the page.
    body = (
        "<html><head><title>Business Software and Services Reviews | Acme</title></head><body>"
        '<header><nav>Home Products Pricing <a href="/login">Log in</a></nav></header>'
        f"<main><h1>Top Business Software</h1><p>{_LONG}</p>"
        "<p>Log in to view more reviews.</p>"
        '<a href="https://accounts.google.com/o/oauth2/v2/auth">Log in with Google</a>'
        "</main></body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL


def test_content_rich_article_with_member_login_sidebar_is_not_a_wall():
    # A complete, fully-readable article with a member-login sidebar (a password input) and a weak
    # "sign in to view your saved articles" CTA. The article IS present; the login is a feature, not a
    # wall. A weak "...to view" CTA must not promote a content-rich page to LOGIN_WALL via the
    # password branch (the symmetric case of the SSO false positive).
    body = (
        "<html><head><title>City Council Approves Budget</title></head><body><main>"
        f"<article><h1>City Council Approves Budget</h1><p>{_LONG}</p></article>"
        '<aside><p>Sign in to view your saved articles.</p>'
        '<form action="/login"><input type="password" name="pw"></form></aside>'
        "</main></body></html>"
    )
    assert _verdict(body) is not Verdict.LOGIN_WALL
