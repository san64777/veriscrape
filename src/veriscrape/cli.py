"""`veriscrape` command-line interface.

    veriscrape check https://example.com        # fetch + classify a live URL
    veriscrape check --file response.html        # classify a saved response (no network)
    veriscrape check https://example.com --json  # machine-readable

Exit code is pipeline-friendly: 0 when the content looks fine (OK / UNVERIFIED),
1 when veriscrape detects a problem (BLOCKED / CHALLENGE / SOFT_404 / ...).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import FetchRecord, Verdict, classify, get

_OK_VERDICTS = frozenset({Verdict.OK, Verdict.UNVERIFIED})


def format_record(record: FetchRecord) -> str:
    """One-line-ish human summary of a FetchRecord."""
    mark = "OK " if record.verdict in _OK_VERDICTS else "!! "
    head = f"{mark}{record.verdict.value}"
    if record.cause:
        head += f" ({record.cause})"
    if record.confidence:
        head += f"  confidence={record.confidence:.2f}"
    return f"{record.url}\n  {head}\n  HTTP {record.status}"


def _classify_file(path: str) -> FetchRecord:
    body = Path(path).read_text(errors="replace")
    verdict, cause, confidence, evidence = classify(status=200, headers={}, body=body)
    return FetchRecord(
        url=f"file://{path}", status=200, verdict=verdict, cause=cause,
        confidence=confidence, evidence=evidence, text=body,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veriscrape", description="fetch, but it tells you the truth.")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="fetch (or read) a response and report its trust verdict")
    check.add_argument("target", help="a URL, or a file path with --file")
    check.add_argument("--file", action="store_true", help="read target as a saved response file")
    check.add_argument("--json", action="store_true", help="emit the FetchRecord as JSON")
    args = parser.parse_args(argv)

    if args.command == "check":
        record = _classify_file(args.target) if args.file else get(args.target)
        if args.json:
            print(record.model_dump_json(indent=2, exclude={"text"}))
        else:
            print(format_record(record))
        return 0 if record.verdict in _OK_VERDICTS else 1
    return 2  # unreachable: subparser is required


if __name__ == "__main__":
    raise SystemExit(main())
