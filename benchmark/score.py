"""Scoring for the veriscrape reliability benchmark.

The headline is the SILENT FAILURE: a tool returns a 2xx "success" response whose
content veriscrape detects as actually blocked / challenged / a gate / a husk /
a soft-404, and the tool did not flag it. Status-code-only retry logic (the
industry default) never catches these, so the corruption is stored as data.
"""

from __future__ import annotations

from collections import Counter

NEGATIVE_VERDICTS = frozenset(
    {"BLOCKED", "CHALLENGE", "HONEYPOT", "SOFT_404", "LOGIN_WALL", "EMPTY_SHELL"}
)


def is_silent_failure(status: int | None, verdict: str, tool_flagged_block: bool) -> bool:
    """True when a 2xx response hid a real problem the tool did not flag."""
    if status is None or not (200 <= status < 300):
        return False  # a non-2xx status already signals a problem, not silent
    if tool_flagged_block:
        return False  # the tool warned you, not silent
    return verdict in NEGATIVE_VERDICTS


def aggregate_runs(runs: list[dict]) -> dict:
    """Collapse N runs of one (tool x target) cell into a stable summary.

    Anti-bot is probabilistic, so a single request is fragile. We report the MODAL verdict and a
    stability fraction (how many of N runs agreed), and base the silent-failure call on the modal.
    """
    statuses = Counter(run["status"] for run in runs)
    verdicts = Counter(run["verdict"] for run in runs)
    modal_status = statuses.most_common(1)[0][0]
    modal_verdict, modal_count = verdicts.most_common(1)[0]
    flagged = any(run["tool_flagged_block"] for run in runs)
    return {
        "runs": len(runs),
        "status": modal_status,
        "verdict": modal_verdict,
        "stability": f"{modal_count}/{len(runs)}",
        "tool_flagged_block": flagged,
        "silent_failure": is_silent_failure(modal_status, modal_verdict, flagged),
    }


def summarize(cells: list[dict]) -> dict[str, dict]:
    """SELF-GRADED legacy metric: silent failures judged by veriscrape's OWN verdict, denominator =
    all cells. This is the circular number the de-circularized harness replaced. NOT the published
    number: use ``summarize_truth`` (scored against the independent true_verdict) instead. Kept only
    for its existing unit test.
    """
    by_tool: dict[str, dict] = {}
    for cell in cells:
        tool = by_tool.setdefault(cell["tool"], {"cells": 0, "silent_failures": 0})
        tool["cells"] += 1
        if cell.get("silent_failure"):
            tool["silent_failures"] += 1
    for tool in by_tool.values():
        tool["silent_failure_rate"] = (
            round(tool["silent_failures"] / tool["cells"], 3) if tool["cells"] else 0.0
        )
    return by_tool


def classify_agreement(cells: list[dict]) -> dict:
    """How often veriscrape's own verdict matched the INDEPENDENT true_verdict.

    This is the de-circularizing number: the headline silent-failure rate is judged against the
    hand label (``summarize_truth``), and this reports separately how accurate veriscrape was against
    that same independent ground truth. Cells without a true_verdict are excluded.
    """
    labeled = [c for c in cells if c.get("true_verdict")]
    agree = sum(1 for c in labeled if c.get("classify_verdict") == c["true_verdict"])
    n = len(labeled)
    return {"labeled": n, "agree": agree, "rate": round(agree / n, 3) if n else 0.0}


def summarize_truth(cells: list[dict]) -> dict[str, dict]:
    """Per-tool silent-failure scored against the INDEPENDENT true_verdict, not veriscrape's verdict.

    The denominator is only the 2xx-eligible cells: a non-2xx response already signalled a problem,
    so it cannot be a silent failure and does not belong in the rate. Cells without a true_verdict
    are skipped (unlabeled).
    """
    by_tool: dict[str, dict] = {}
    for cell in cells:
        true_verdict = cell.get("true_verdict")
        if not true_verdict:
            continue
        tool = by_tool.setdefault(cell["tool"], {"eligible": 0, "silent_failures": 0})
        status = cell.get("status")
        if status is None or not (200 <= status < 300):
            continue  # non-2xx is not eligible to be a silent failure
        tool["eligible"] += 1
        if is_silent_failure(status, true_verdict, cell.get("tool_flagged_block", False)):
            tool["silent_failures"] += 1
    for tool in by_tool.values():
        tool["rate"] = round(tool["silent_failures"] / tool["eligible"], 3) if tool["eligible"] else 0.0
    return by_tool
