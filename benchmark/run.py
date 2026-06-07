"""Run the veriscrape reliability benchmark: tools x targets -> verdicts -> the finding.

For each (tool x target): fetch with the tool, classify the response with veriscrape (using
the REAL response headers, so header signals like the DataDome cookie fire), and record whether
it was a SILENT FAILURE: a 2xx 'success' that is actually junk the tool did not flag.

Writes a dated results JSON and prints the scoring table.

Usage:
    uv run --extra benchmark python -m benchmark.run
    uv run --extra benchmark python -m benchmark.run --date 2026-06-07
"""

from __future__ import annotations

import argparse
import json
import time
import tomllib
from pathlib import Path

from veriscrape import classify
from benchmark.score import aggregate_runs, summarize

HERE = Path(__file__).parent
# Status codes Scrapling/Scrapy treat as "blocked" (status-code-only detection, the baseline).
_STATUS_BLOCK_CODES = frozenset({401, 403, 407, 429, 444, 500, 502, 503, 504})
_RUN_DELAY = 0.3  # polite pause between repeated requests to the same target


def fetch_requests(url: str):
    import requests

    r = requests.get(url, timeout=25)
    return r.status_code, dict(r.headers), r.text, False  # requests makes no block claim


def fetch_curl_cffi(url: str):
    from curl_cffi import requests as cffi

    r = cffi.get(url, impersonate="chrome", timeout=25)
    return r.status_code, dict(r.headers), r.text, False  # curl_cffi makes no block claim


def fetch_scrapling(url: str):
    # Scrapling advertises "blocked request detection", but its mechanism is status-code matching,
    # so it flags non-2xx but silently passes a 200 husk/gate. We record that status-code claim.
    from scrapling.fetchers import Fetcher

    page = Fetcher.get(url, timeout=25)
    status = page.status
    try:
        headers = dict(page.headers or {})
    except Exception:
        headers = {}
    body = page.html_content or getattr(page, "body", "") or ""
    flagged = status in _STATUS_BLOCK_CODES
    return status, headers, body, flagged


def available_tools() -> dict:
    tools = {"requests": fetch_requests, "curl_cffi": fetch_curl_cffi}
    try:
        import scrapling  # noqa: F401

        tools["scrapling"] = fetch_scrapling
    except Exception:
        pass  # Scrapling not installed; it's an optional comparison tool.
    return tools


def run(tools: dict, targets: list[dict], n_runs: int = 3) -> list[dict]:
    cells: list[dict] = []
    for tool_name, fetch in tools.items():
        for target in targets:
            url, tier = target["url"], target["tier"]
            runs: list[dict] = []
            error = None
            for _ in range(n_runs):
                try:
                    status, headers, body, flagged = fetch(url)
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                    time.sleep(_RUN_DELAY)
                    continue
                verdict, cause, _, _ = classify(status=status, headers=headers, body=body)
                runs.append(
                    {"status": status, "verdict": verdict.value, "cause": cause,
                     "tool_flagged_block": flagged}
                )
                time.sleep(_RUN_DELAY)
            if not runs:
                cells.append(
                    {"tool": tool_name, "tier": tier, "url": url, "status": None, "error": error,
                     "verdict": None, "cause": None, "runs": 0, "stability": f"0/{n_runs}",
                     "tool_flagged_block": False, "silent_failure": False}
                )
                continue
            agg = aggregate_runs(runs)
            cause = next((r["cause"] for r in runs if r["verdict"] == agg["verdict"] and r.get("cause")), None)
            cells.append({"tool": tool_name, "tier": tier, "url": url, "cause": cause, **agg})
    return cells


def render_table(cells: list[dict], summary: dict, date: str) -> str:
    lines = [f"# veriscrape reliability benchmark: {date}", ""]
    lines.append("Each cell: what the tool returned, and what veriscrape detected the content to be.")
    lines.append("A **silent failure** = a 2xx 'success' whose content is actually junk, unflagged.\n")
    lines.append("| tool | tier | url | HTTP | veriscrape verdict | cause | stability | silent? |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for c in cells:
        sf = "🔴 **SILENT**" if c["silent_failure"] else ""
        url = c["url"].replace("https://", "")
        lines.append(
            f"| {c['tool']} | {c['tier']} | {url} | {c['status']} | "
            f"{c.get('verdict') or c.get('error','')} | {c.get('cause') or ''} | "
            f"{c.get('stability', '')} | {sf} |"
        )
    lines.append("\n## Silent-failure rate per tool\n")
    lines.append("| tool | cells | silent failures | rate |")
    lines.append("|---|---|---|---|")
    for tool, s in summary.items():
        lines.append(f"| {tool} | {s['cells']} | {s['silent_failures']} | **{s['silent_failure_rate']:.0%}** |")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the veriscrape reliability benchmark.")
    ap.add_argument("--date", default="2026-06-07", help="dated snapshot label")
    ap.add_argument("--targets", default=str(HERE / "targets.toml"))
    ap.add_argument("--runs", type=int, default=3, help="requests per cell (anti-bot is probabilistic)")
    args = ap.parse_args()

    targets = tomllib.loads(Path(args.targets).read_text())["targets"]
    tools = available_tools()
    print(f"tools: {list(tools)}  targets: {len(targets)}  runs/cell: {args.runs}")

    cells = run(tools, targets, n_runs=args.runs)
    summary = summarize(cells)

    results = {"date": args.date, "tools": list(tools), "summary": summary, "cells": cells}
    (HERE / f"results-{args.date}.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    table = render_table(cells, summary, args.date)
    (HERE / f"results-{args.date}.md").write_text(table)
    print("\n" + table)


if __name__ == "__main__":
    main()
