"""The FetchRecord: veriscrape's spine.

Every fetch returns one of these: the bytes you asked for, plus a portable,
serializable verdict about whether those bytes can be trusted. The same record
shape travels across stacks (requests / Scrapy / Playwright) and is stored as
plain JSON the user owns, deliberately not a serverless-hostile local DB.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """What we believe the response actually is, independent of its status code.

    A 200 is not ground truth. The verdict is.
    """

    OK = "OK"                    # genuine origin content
    BLOCKED = "BLOCKED"          # a hard anti-bot wall or deny page
    CHALLENGE = "CHALLENGE"      # a JS/CAPTCHA interstitial (solvable, not content)
    HONEYPOT = "HONEYPOT"        # a decoy or AI-Labyrinth trap page
    SOFT_404 = "SOFT_404"        # a "not found" served as 200
    LOGIN_WALL = "LOGIN_WALL"    # a sign-in or paywall gate instead of the data
    EMPTY_SHELL = "EMPTY_SHELL"  # a JS app skeleton with no server-rendered content
    UNVERIFIED = "UNVERIFIED"    # we could not tell, so abstain rather than guess


class FetchRecord(BaseModel):
    """A portable, dated verdict about a single fetch.

    This object is the contract every later module reads, writes, or acts on.
    Keep it boring and serializable: ``record.model_dump_json()`` is the whole
    portability story.
    """

    url: str
    status: int | None = None
    verdict: Verdict = Verdict.UNVERIFIED
    cause: str | None = None          # e.g. "cloudflare_challenge", "datadome", "ai_labyrinth"
    tactic: str | None = None         # what transport produced this, e.g. "curl_cffi:chrome"
    confidence: float = 0.0           # 0.0 to 1.0
    evidence: dict[str, Any] = Field(default_factory=dict)  # the markers we matched, for audit
    headers: dict[str, str] = Field(default_factory=dict)
    text: str | None = None           # the response body
    elapsed_ms: float | None = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def ok(self) -> bool:
        """True only when we positively believe this is real content.

        Note the asymmetry: UNVERIFIED is *not* ok. We never report success we
        cannot evidence: a confident-but-wrong OK is the exact failure
        veriscrape exists to prevent.
        """
        return self.verdict is Verdict.OK
