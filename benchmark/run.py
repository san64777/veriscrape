"""Run the veriscrape reliability benchmark: tools x targets -> captured bodies -> the finding.

De-circularized by design. For each (tool x target) we:
  1. fetch with the tool, capturing the RAW response (status, headers, body) to ``captures/<date>/``
     so the evidence is captured locally for re-checking (captures/ is gitignored, not a committed dataset);
  2. record what veriscrape's classifier PREDICTS (``classify_verdict``), kept separate from
  3. an INDEPENDENT ``true_verdict`` hand label (``labels-<date>.toml``), assigned by reading the
     captured body, NOT by trusting the classifier.

The headline silent-failure rate is scored against the independent label (``summarize_truth``); a
second number reports how often veriscrape AGREED with that label (``classify_agreement``), which is
its real, non-circular accuracy. ``results-2026-06-07.md`` is the older self-graded snapshot and is
left untouched.

Usage:
    uv run --extra benchmark python -m benchmark.run --date 2026-06-08       # collect + capture
    uv run --extra benchmark python -m benchmark.run --date 2026-06-08 --render   # re-render after labeling
"""

from __future__ import annotations

import argparse
import json
import re
import time
import tomllib
from pathlib import Path

from veriscrape import classify
from benchmark.score import aggregate_runs, classify_agreement, is_silent_failure, summarize_truth

HERE = Path(__file__).parent
# Status codes Scrapling/Scrapy treat as "blocked" (status-code-only detection, the baseline).
_STATUS_BLOCK_CODES = frozenset({401, 403, 407, 429, 444, 500, 502, 503, 504})
_RUN_DELAY = 0.3  # polite pause between repeated requests to the same target
_BODY_CAP = 60000  # chars of body persisted per capture, enough to verify the verdict, bounds the repo


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
    # so it flags non-2xx but silently passes a 200 husk/gate. We record that status-code claim
    # (this is our MODEL of a status-code baseline, labelled as such in the write-up, not a call into
    # Scrapling's internal adaptor).
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


def _slug(tool: str, url: str) -> str:
    host = re.sub(r"^https?://", "", url)
    host = re.sub(r"[^a-zA-Z0-9]+", "_", host).strip("_")[:50]
    return f"{tool}__{host}"


def capture_body(date: str, tool: str, url: str, status, headers: dict, body: str) -> str:
    """Persist one raw response as committed evidence; return its repo-relative path."""
    cap_dir = HERE / "captures" / date
    cap_dir.mkdir(parents=True, exist_ok=True)
    truncated = len(body) > _BODY_CAP
    record = {
        "url": url,
        "tool": tool,
        "status": status,
        "headers": headers,
        "body": body[:_BODY_CAP],
        "body_truncated": truncated,
        "body_full_len": len(body),
        # Independent ground truth, hand-assigned by reading THIS body (see labels-<date>.toml).
        "true_verdict": None,
    }
    path = cap_dir / f"{_slug(tool, url)}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False))
    return str(path.relative_to(HERE))


def collect(tools: dict, targets: list[dict], date: str, n_runs: int = 3) -> list[dict]:
    cells: list[dict] = []
    for tool_name, fetch in tools.items():
        for target in targets:
            url, tier = target["url"], target["tier"]
            runs: list[dict] = []
            error = None
            capture = None
            for i in range(n_runs):
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
                if capture is None:  # commit the body once per cell (responses are stable across runs)
                    capture = capture_body(date, tool_name, url, status, headers, body)
                time.sleep(_RUN_DELAY)
            if not runs:
                cells.append(
                    {"tool": tool_name, "tier": tier, "url": url, "status": None, "error": error,
                     "classify_verdict": None, "classify_cause": None, "true_verdict": None,
                     "runs": 0, "stability": f"0/{n_runs}", "tool_flagged_block": False, "capture": None}
                )
                continue
            agg = aggregate_runs(runs)
            cause = next((r["cause"] for r in runs if r["verdict"] == agg["verdict"] and r.get("cause")), None)
            cells.append({
                "tool": tool_name, "tier": tier, "url": url, "status": agg["status"],
                "stability": agg["stability"], "tool_flagged_block": agg["tool_flagged_block"],
                "classify_verdict": agg["verdict"], "classify_cause": cause,
                "true_verdict": None, "capture": capture,
            })
    return cells


def apply_labels(cells: list[dict], labels: dict) -> None:
    """Merge the independent true_verdict labels (keyed by capture path) into the cells, in place."""
    for cell in cells:
        cap = cell.get("capture")
        if cap and cap in labels:
            cell["true_verdict"] = labels[cap].get("true_verdict")


def render_truth(cells: list[dict], date: str) -> str:
    truth = summarize_truth(cells)
    agree = classify_agreement(cells)
    lines = [f"# veriscrape reliability benchmark (de-circularized): {date}", ""]
    lines.append(
        "Each cell is judged against an INDEPENDENT `true_verdict` (hand-assigned by reading the "
        "committed raw body in `captures/" + date + "/`), NOT by veriscrape. A **silent failure** = a "
        "2xx 'success' whose true content is junk and the tool did not flag it. The final column shows "
        "whether veriscrape's own verdict matched the independent label.\n"
    )
    lines.append("| tool | tier | url | HTTP | true verdict | veriscrape | match | silent? | capture |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for c in cells:
        tv = c.get("true_verdict") or "?"
        cv = c.get("classify_verdict") or c.get("error", "") or "?"
        match = "ok" if c.get("true_verdict") and c.get("classify_verdict") == c.get("true_verdict") else (
            "" if not c.get("true_verdict") else "MISS")
        silent = ""
        if c.get("true_verdict") and c.get("status") is not None and 200 <= c["status"] < 300:
            if is_silent_failure(c["status"], c["true_verdict"], c.get("tool_flagged_block", False)):
                silent = "SILENT"
        cap = c.get("capture") or ""
        cap_link = f"[body]({cap.replace('benchmark/', '')})" if cap else ""
        lines.append(
            f"| {c['tool']} | {c['tier']} | {c['url'].replace('https://','')} | {c.get('status')} | "
            f"{tv} | {cv} | {match} | {silent} | {cap_link} |"
        )
    lines.append("\n## Silent-failure rate per tool (scored against the independent label)\n")
    lines.append("| tool | 2xx-eligible cells | silent failures | rate |")
    lines.append("|---|---|---|---|")
    for tool, s in truth.items():
        lines.append(f"| {tool} | {s['eligible']} | {s['silent_failures']} | **{s['silent_failures']}/{s['eligible']} ({s['rate']:.0%})** |")
    lines.append(
        f"\n## veriscrape accuracy vs the independent labels\n\n"
        f"veriscrape's verdict matched the hand label on **{agree['agree']}/{agree['labeled']}** "
        f"labeled cells ({agree['rate']:.0%}). This is the de-circularizing number: the silent-failure "
        f"rates above are judged by the independent label, and this reports how often the classifier "
        f"agreed with that same ground truth.\n"
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the veriscrape reliability benchmark.")
    ap.add_argument("--date", default="2026-06-08", help="dated snapshot label")
    ap.add_argument("--targets", default=str(HERE / "targets.toml"))
    ap.add_argument("--runs", type=int, default=3, help="requests per cell (anti-bot is probabilistic)")
    ap.add_argument("--render", action="store_true", help="re-render the MD from an already-labeled results JSON")
    args = ap.parse_args()

    results_json = HERE / f"results-{args.date}.json"
    labels_path = HERE / f"labels-{args.date}.toml"

    if args.render:
        results = json.loads(results_json.read_text())
        cells = results["cells"]
    else:
        targets = tomllib.loads(Path(args.targets).read_text())["targets"]
        tools = available_tools()
        print(f"tools: {list(tools)}  targets: {len(targets)}  runs/cell: {args.runs}")
        cells = collect(tools, targets, args.date, n_runs=args.runs)

    labels = tomllib.loads(labels_path.read_text()).get("label", {}) if labels_path.exists() else {}
    if labels:
        apply_labels(cells, labels)

    results = {"date": args.date, "cells": cells}
    results_json.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    table = render_truth(cells, args.date)
    (HERE / f"results-{args.date}.md").write_text(table)
    print("\n" + table)


if __name__ == "__main__":
    main()
