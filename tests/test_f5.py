"""F5 BIG-IP ASM (Advanced WAF) block detection.

The deny template ('The requested URL was rejected ... Your support ID is: <id>') is
F5-ASM-specific, gated by a non-2xx status so a blog quoting it (200) does not fire.
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def test_f5_asm_block_is_detected():
    verdict, cause, confidence, _ = classify_fixture("f5_block.json")
    assert verdict is Verdict.BLOCKED
    assert cause == "f5_block"


def test_blog_quoting_f5_template_is_not_flagged():
    # 200 blog quoting the F5 template; the non-2xx status gate must reject it.
    verdict, *_ = classify_fixture("f5_fp_blog.json")
    assert verdict is not Verdict.BLOCKED


def test_f5_fronted_allowed_200_is_not_flagged():
    # A page behind an F5 BIG-IP load balancer (TS cookie) with real content is not a block.
    body = "<html><body><main><h1>Welcome</h1><p>Real content here, plenty of it.</p></main></body></html>"
    verdict, *_ = classify(status=200, headers={"set-cookie": "TS0123456789=abc; Path=/"}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_f5_help_page_404_quoting_template_is_not_blocked():
    # A help/docs page that explains the F5 message, served at 404, must abstain; the prose has no
    # real "support ID is: <digits>" line.
    body = (
        "<html><body><h1>What does 'The requested URL was rejected' mean?</h1>"
        "<p>If you see 'Your support ID is' on an F5 page, contact the site owner.</p></body></html>"
    )
    verdict, *_ = classify(status=404, headers={}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_f5_app_error_quoting_support_id_is_not_blocked():
    # An app's own 500 that mentions a help-desk "support ID" (no colon+digits) must abstain.
    body = (
        "<html><body>The requested URL was rejected by our upstream. "
        "Quote your support ID to our help desk.</body></html>"
    )
    verdict, *_ = classify(status=500, headers={}, body=body)
    assert verdict is not Verdict.BLOCKED


def test_f5_block_with_split_tags_is_detected():
    # The real deny page with the ID wrapped in inline tags must still be caught (de-tag).
    body = (
        "<html><body>The requested URL was rejected. Please consult with your administrator.<br><br>"
        "Your support <b>ID</b> is: 1234567890</body></html>"
    )
    verdict, cause, *_ = classify(status=403, headers={}, body=body)
    assert verdict is Verdict.BLOCKED
    assert cause == "f5_block"
