"""Honeypot detection: the TRAP STRUCTURE, not the prose.

A well-made AI-Labyrinth decoy reads like a normal article, so content forensics fail.
The body-only signal we CAN trust: a cluster of INVISIBLE nofollow links into a same-host
maze. (The strongest signal, arriving via an invisible link, needs get()-level context.)
"""

import json
import pathlib

from veriscrape import Verdict, classify

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def classify_fixture(name):
    d = json.loads((FIXTURES / name).read_text())
    return classify(status=d["status"], headers=d["headers"], body=d["body"])


def _verdict(body, status=200):
    return classify(status=status, headers={}, body=body)[0]


def test_trap_link_cluster_is_honeypot():
    verdict, cause, confidence, evidence = classify_fixture("honeypot_trap_links.json")
    assert verdict is Verdict.HONEYPOT
    assert cause == "trap_links"
    assert confidence >= 0.8


def test_normal_article_is_not_honeypot():
    body = (
        "<html><head><title>A Real Article</title></head><body><article><h1>A Real Article</h1>"
        "<p>" + "words " * 80 + "</p>"
        '<a href="/related-1">Related one</a> <a href="https://other.example">A source</a>'
        "</article></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


def test_single_hidden_skipnav_link_is_not_honeypot():
    # One hidden link (a skip-to-content accessibility link) is normal, not a maze.
    body = (
        '<html><body><a href="#main" style="display:none">Skip to content</a>'
        "<main><h1>Page</h1><p>Hello.</p></main></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


def test_visible_nofollow_links_are_not_honeypot():
    # Plenty of real pages have visible nofollow links (user-generated content, ads), not a trap.
    body = (
        "<html><body><article><h1>Forum thread</h1>"
        '<a href="https://a.example" rel="nofollow">link a</a>'
        '<a href="https://b.example" rel="nofollow">link b</a>'
        '<a href="https://c.example" rel="nofollow">link c</a>'
        '<a href="https://d.example" rel="nofollow">link d</a>'
        "</article></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


# --- false-positive guards: hidden nofollow links that are NOT a same-host deep maze ---

def test_hidden_social_share_cluster_is_not_honeypot():
    body = (
        '<html><body><div class="share">'
        '<a href="https://twitter.com/intent/tweet" rel="nofollow noopener" style="display:none">Tweet</a>'
        '<a href="https://facebook.com/sharer" rel="nofollow noopener" style="display:none">Share</a>'
        '<a href="https://linkedin.com/share" rel="nofollow noopener" style="display:none">LinkedIn</a>'
        '<a href="mailto:?subject=x" rel="nofollow" style="display:none">Email</a></div>'
        "<article><h1>Post</h1><p>words</p></article></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


def test_skiplink_bundle_is_not_honeypot():
    body = (
        "<html><body>"
        '<a href="#main" rel="nofollow" style="position:absolute;left:-9999px">Skip to content</a>'
        '<a href="#nav" rel="nofollow" style="position:absolute;left:-9999px">Skip to navigation</a>'
        '<a href="#search" rel="nofollow" style="position:absolute;left:-9999px">Skip to search</a>'
        '<a href="#footer" rel="nofollow" style="position:absolute;left:-9999px">Skip to footer</a>'
        "<main><h1>Page</h1></main></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


def test_hidden_nav_drawer_shallow_links_is_not_honeypot():
    body = (
        '<html><body><nav class="drawer">'
        '<a href="/login" rel="nofollow" style="display:none">Sign in</a>'
        '<a href="/cart" rel="nofollow" style="display:none">Cart</a>'
        '<a href="/wishlist" rel="nofollow" style="display:none">Wishlist</a>'
        '<a href="/account" rel="nofollow" style="display:none">My account</a>'
        "</nav><main><h1>Shop</h1></main></body></html>"
    )
    assert _verdict(body) is not Verdict.HONEYPOT


# --- false-negative fixes: more inline-hiding styles, and hidden CONTAINERS ---

def test_inline_hidden_style_variants_are_detected():
    body = (
        "<html><body><article><h1>Decoy</h1><p>words</p></article>"
        '<a href="/maze/0" rel="nofollow" style="font-size:0">a</a>'
        '<a href="/maze/1" rel="nofollow" style="visibility:collapse">b</a>'
        '<a href="/maze/2" rel="nofollow" style="width:0;height:0">c</a>'
        '<a href="/maze/3" rel="nofollow" style="clip:rect(0,0,0,0)">d</a>'
        "</body></html>"
    )
    assert _verdict(body) is Verdict.HONEYPOT


def test_hidden_container_of_trap_links_is_detected():
    inner = "".join(f'<a href="/maze/p{i}" rel="nofollow">link {i}</a>' for i in range(6))
    body = (
        "<html><body><article><h1>Decoy</h1></article>"
        f'<div style="display:none">{inner}</div></body></html>'
    )
    assert _verdict(body) is Verdict.HONEYPOT
