"""Tests for the benchmark's silent-failure scoring."""

from benchmark.score import aggregate_runs, is_silent_failure, summarize


def test_2xx_with_negative_verdict_unflagged_is_silent_failure():
    # The heart of the finding: a 200 'success' that is actually a husk/gate/block, unflagged.
    assert is_silent_failure(200, "EMPTY_SHELL", tool_flagged_block=False) is True
    assert is_silent_failure(200, "LOGIN_WALL", tool_flagged_block=False) is True


def test_2xx_unverified_content_is_not_silent_failure():
    # veriscrape abstains (UNVERIFIED) on real content, not a silent failure.
    assert is_silent_failure(200, "UNVERIFIED", tool_flagged_block=False) is False


def test_non_2xx_is_not_silent_failure():
    # A 403 challenge is not "silent": the status already signals a problem.
    assert is_silent_failure(403, "CHALLENGE", tool_flagged_block=False) is False


def test_flagged_block_is_not_silent():
    # If the tool itself flagged the block, it wasn't silent.
    assert is_silent_failure(200, "BLOCKED", tool_flagged_block=True) is False


def test_aggregate_stable_runs_reports_full_stability():
    runs = [{"status": 200, "verdict": "EMPTY_SHELL", "tool_flagged_block": False}] * 3
    agg = aggregate_runs(runs)
    assert agg["verdict"] == "EMPTY_SHELL"
    assert agg["stability"] == "3/3"
    assert agg["silent_failure"] is True


def test_aggregate_uses_modal_verdict_and_shows_instability():
    runs = [
        {"status": 200, "verdict": "LOGIN_WALL", "tool_flagged_block": False},
        {"status": 200, "verdict": "LOGIN_WALL", "tool_flagged_block": False},
        {"status": 200, "verdict": "UNVERIFIED", "tool_flagged_block": False},
    ]
    agg = aggregate_runs(runs)
    assert agg["verdict"] == "LOGIN_WALL"
    assert agg["stability"] == "2/3"
    assert agg["silent_failure"] is True


def test_summarize_computes_per_tool_rates():
    cells = [
        {"tool": "curl_cffi", "silent_failure": True},
        {"tool": "curl_cffi", "silent_failure": False},
        {"tool": "requests", "silent_failure": True},
        {"tool": "requests", "silent_failure": True},
    ]
    s = summarize(cells)
    assert s["curl_cffi"]["silent_failure_rate"] == 0.5
    assert s["requests"]["silent_failure_rate"] == 1.0
    assert s["curl_cffi"]["silent_failures"] == 1
