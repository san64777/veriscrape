"""veriscrape benchmark harness: the data-collection step.

Fire ONE respectful request at a target with a given tool and save the raw
response (status, headers, body) to ``captures/`` as dated JSON. Those captures
are two things at once:

  1. the evidence behind the neutral finding ("X% of tools return 200 OK with
     blocked/honeypot content and report success"), and
  2. the labeled fixtures the deterministic detectors are built against.

Usage:
    uv run python -m benchmark.harness https://example.com --tool curl_cffi
    uv run python -m benchmark.harness https://example.com --tool requests
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

CAPTURES = Path(__file__).parent / "captures"


def fetch(url: str, tool: str) -> dict:
    if tool == "requests":
        import requests

        resp = requests.get(url, timeout=30)
        status, headers, body = resp.status_code, dict(resp.headers), resp.text
    elif tool == "curl_cffi":
        from curl_cffi import requests as cffi

        resp = cffi.get(url, impersonate="chrome", timeout=30)
        status, headers, body = resp.status_code, dict(resp.headers), resp.text
    else:
        raise SystemExit(f"unknown tool: {tool!r}")

    return {
        "url": url,
        "tool": tool,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "headers": headers,
        "body": body,
        # You hand-label this. It becomes the expected value of a test fixture.
        # One of: OK | BLOCKED | CHALLENGE | HONEYPOT | SOFT_404 | LOGIN_WALL | EMPTY_SHELL
        "true_verdict": None,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Capture one raw response for the veriscrape benchmark.")
    ap.add_argument("url")
    ap.add_argument("--tool", default="curl_cffi", choices=["curl_cffi", "requests"])
    args = ap.parse_args()

    record = fetch(args.url, args.tool)
    CAPTURES.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = args.url.split("://", 1)[-1].replace("/", "_")[:60]
    out = CAPTURES / f"{stamp}_{args.tool}_{host}.json"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False))

    print(f"saved {out}  (status={record['status']}, {len(record['body'])} bytes)")
    print('next: open it, set "true_verdict" by eye, then curate it into tests/fixtures/.')


if __name__ == "__main__":
    main()
