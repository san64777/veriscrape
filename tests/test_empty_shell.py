"""Empty-shell detection: a 200 that is a JS app skeleton with no real content.

The honest signal is not "low visible text" alone (nowsecure.nl is 90% scripts
with ~0 server-rendered text yet is a real allowed page). It is low visible text
+ a substantial body + a JS-app-skeleton marker (an empty mount div or a
JS-required notice). The negative fixtures here are live captures, so they guard
against the naive text-only rule.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_empty_js_shell_is_detected():
    verdict, cause, confidence, evidence = classify_fixture("empty_shell_discord.json")
    assert verdict is Verdict.EMPTY_SHELL
    assert cause == "js_app_shell"
    assert confidence >= 0.9


def test_server_rendered_page_is_not_empty_shell():
    # Real server-rendered page (HN) with plenty of visible text.
    verdict, *_ = classify_fixture("control_hn.json")
    assert verdict is not Verdict.EMPTY_SHELL


def test_tiny_real_page_is_not_empty_shell():
    # example.com is a small but real page, below the size floor, so must not be flagged.
    verdict, *_ = classify_fixture("control_example.json")
    assert verdict is not Verdict.EMPTY_SHELL


def test_script_heavy_page_without_mount_is_not_empty_shell():
    # Live nowsecure.nl is ~0 visible text and 90% scripts, but has NO mount div and no
    # JS-required notice, so the detector must require that marker, not fire on low text alone.
    verdict, *_ = classify_fixture("cloudflare_allowed_nowsecure.json")
    assert verdict is not Verdict.EMPTY_SHELL


# Padding to clear the size floor without adding visible text.
_PAD = "<script>/* padding to clear the size floor */</script>" * 50


def test_canvas_app_in_mount_is_not_empty_shell():
    # A real map/canvas app: the mount holds a <canvas> (an element child), not a text husk.
    body = f"<html><head>{_PAD}</head><body><div id='app'><canvas></canvas></div></body></html>"
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.EMPTY_SHELL


def test_short_ssr_page_with_noscript_notice_is_not_empty_shell():
    # Filled mount + the standard framework <noscript> enable-JS notice + short real content.
    # The data was server-rendered and IS present, so the notice alone must not flip the verdict.
    body = (
        f"<html><head>{_PAD}</head><body>"
        "<noscript>You need to enable JavaScript to run this app.</noscript>"
        "<div id='root'><h1>System Status</h1><p>All systems operational.</p></div>"
        "</body></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.EMPTY_SHELL


def test_angular_app_root_shell_is_detected():
    # Angular mounts into a custom <app-root> element (no id); an empty one is a true shell.
    body = f"<html><head><title>App</title>{_PAD}</head><body><app-root></app-root></body></html>"
    verdict, cause, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.EMPTY_SHELL
    assert cause == "js_app_shell"


def test_tiny_angular_bootstrap_is_detected():
    # A ~360-byte Angular bootstrap (empty <app-root> + module script), below the OLD 2KB floor,
    # but a genuine shell. The empty-husk mount + a <script> keep this safe to detect.
    verdict, cause, *_ = classify_fixture("empty_shell_angular_bootstrap.json")
    assert verdict is Verdict.EMPTY_SHELL
    assert cause == "js_app_shell"


def test_js_redirect_stub_is_not_empty_shell():
    # A tiny JS-redirect page (no mount husk) must NOT be flagged: it's a redirect, not a shell.
    body = (
        "<!DOCTYPE html><html><head><script>window.location.replace('/home');</script>"
        "</head></html>"
    )
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.EMPTY_SHELL


def test_custom_element_shell_is_detected():
    # A SPA mounting into a custom element (<cm-app>, like real <cm-certemy>), not a known id/app-root.
    verdict, cause, *_ = classify_fixture("empty_shell_custom_element.json")
    assert verdict is Verdict.EMPTY_SHELL
    assert cause == "js_app_shell"


def test_custom_element_with_loading_placeholder_is_detected():
    # certemy-style: the mount shows only a short "Loading..." placeholder until JS renders.
    body = f"<html><head>{_PAD}</head><body><cm-app>Loading...</cm-app></body></html>"
    verdict, cause, *_ = classify(status=200, headers={}, body=body)
    assert verdict is Verdict.EMPTY_SHELL
    assert cause == "js_app_shell"


def test_custom_element_with_real_text_is_not_a_shell():
    # A mount holding a real (if short) sentence is rendered content, not a loading placeholder.
    body = f"<html><head>{_PAD}</head><body><cm-note>Your account balance is current.</cm-note></body></html>"
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.EMPTY_SHELL


def test_content_rich_page_with_custom_element_is_not_a_shell():
    # A real content page that happens to use a web component (an empty <my-icon>) is NOT a shell.
    body = (
        "<html><head>" + _PAD + "</head><body><my-icon></my-icon>"
        "<main><h1>A Real Article</h1><p>" + "words " * 80 + "</p></main></body></html>"
    )
    assert classify(status=200, headers={}, body=body)[0] is not Verdict.EMPTY_SHELL


def test_filled_custom_element_is_not_a_shell():
    # A custom element that is server-rendered with content is not a husk.
    body = f"<html><head>{_PAD}</head><body><cm-app><h1>Welcome</h1><p>Hello there.</p></cm-app></body></html>"
    assert classify(status=200, headers={}, body=body)[0] is not Verdict.EMPTY_SHELL


def test_empty_mount_without_a_script_is_not_empty_shell():
    # An empty mount but no script is not a JS app skeleton: a shell always ships scripts.
    # Padded over the size floor (via a comment) so this exercises the script requirement, not the floor.
    body = "<html><body><div id='root'></div><!-- " + "x" * 400 + " --></body></html>"
    verdict, *_ = classify(status=200, headers={}, body=body)
    assert verdict is not Verdict.EMPTY_SHELL
