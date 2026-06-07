# Security Policy

## Reporting a vulnerability

veriscrape computes trust verdicts from untrusted page content, so a parsing or
classification bug can affect downstream data pipelines. If you find a security
issue, please email **san64777@gmail.com** instead of opening a public issue.
I will acknowledge within a few days and work with you on a fix and a disclosure
timeline.

## What is in scope

veriscrape is a deterministic library. It fetches a URL and classifies the
response from status, headers, and body. It runs no untrusted code and makes no
network calls beyond the fetch you ask for. Realistic concerns:

- A crafted page that makes the classifier crash, hang, or consume excessive
  memory or CPU.
- A way to make `classify` return a confident wrong verdict that a caller would
  trust (note: returning `UNVERIFIED` when unsure is by design, not a bug).

## What is not a security issue

The classifier being wrong on some page is a **detection report**, not a
vulnerability. Please open a normal issue with a non-sensitive reproduction.

## Supported versions

The latest released version on PyPI receives fixes.
