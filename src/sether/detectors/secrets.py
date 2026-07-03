"""Secrets detector pack: API keys, access tokens, high-entropy strings.

Direct port of ``src/detectors/secrets.ts``. Where vendor docs publish official
patterns we follow them; otherwise we use conservative prefix + length +
character-class rules that match real keys without flagging arbitrary
base64/hex blobs. Every regex is a single bounded character class.
"""

from __future__ import annotations

import math
import re
from typing import List

from .types import DetectorMatch


def _match_all(text: str, pattern: "re.Pattern[str]") -> List[DetectorMatch]:
    return [DetectorMatch(m.start(), m.end(), m.group(0)) for m in pattern.finditer(text)]


# --- AWS access key ---------------------------------------------------------

_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b", re.ASCII)


class _AwsAccessKeyDetector:
    type = "AWS_KEY"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _AWS_ACCESS_KEY_RE)


aws_access_key_detector = _AwsAccessKeyDetector()


# --- OpenAI -----------------------------------------------------------------

_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b", re.ASCII)


class _OpenAIKeyDetector:
    type = "OPENAI_KEY"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _OPENAI_KEY_RE.finditer(text):
            if not m.group(0).startswith("sk-"):
                continue
            matches.append(DetectorMatch(m.start(), m.end(), m.group(0)))
        return matches


openai_key_detector = _OpenAIKeyDetector()


# --- Anthropic --------------------------------------------------------------

_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-(?:api\d{2}-|admin\d{2}-)[A-Za-z0-9_-]{40,}\b", re.ASCII)


class _AnthropicKeyDetector:
    type = "ANTHROPIC_KEY"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _ANTHROPIC_KEY_RE)


anthropic_key_detector = _AnthropicKeyDetector()


# --- GitHub -----------------------------------------------------------------

_GITHUB_PAT_CLASSIC_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b", re.ASCII)
_GITHUB_PAT_FINEGRAINED_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b", re.ASCII)


class _GithubPatDetector:
    type = "GITHUB_PAT"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _GITHUB_PAT_CLASSIC_RE) + _match_all(text, _GITHUB_PAT_FINEGRAINED_RE)


github_pat_detector = _GithubPatDetector()


# --- Slack ------------------------------------------------------------------

_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-\d{10,12}-\d{10,13}-[A-Za-z0-9]{24,34}\b", re.ASCII)


class _SlackTokenDetector:
    type = "SLACK_TOKEN"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _SLACK_TOKEN_RE)


slack_token_detector = _SlackTokenDetector()


# --- Stripe -----------------------------------------------------------------

_STRIPE_KEY_RE = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b", re.ASCII)
_STRIPE_WHSEC_RE = re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b", re.ASCII)


class _StripeKeyDetector:
    type = "STRIPE_KEY"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _STRIPE_KEY_RE) + _match_all(text, _STRIPE_WHSEC_RE)


stripe_key_detector = _StripeKeyDetector()


# --- JWT --------------------------------------------------------------------

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", re.ASCII)


class _JwtDetector:
    type = "JWT"

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, _JWT_RE)


jwt_detector = _JwtDetector()


# --- High entropy -----------------------------------------------------------

_HIGH_ENTROPY_CANDIDATE = re.compile(r"\b[A-Za-z0-9_-]{32,128}\b", re.ASCII)
_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"\d")


def _shannon_entropy(s: str) -> float:
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    h = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        h -= p * math.log2(p)
    return h


class _HighEntropyDetector:
    type = "HIGH_ENTROPY"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _HIGH_ENTROPY_CANDIDATE.finditer(text):
            candidate = m.group(0)
            if not _HAS_LETTER.search(candidate):
                continue
            if not _HAS_DIGIT.search(candidate):
                continue
            if _shannon_entropy(candidate) < 3.5:
                continue
            matches.append(DetectorMatch(m.start(), m.start() + len(candidate), candidate))
        return matches


high_entropy_detector = _HighEntropyDetector()


secrets_detectors = (
    aws_access_key_detector,
    openai_key_detector,
    anthropic_key_detector,
    github_pat_detector,
    slack_token_detector,
    stripe_key_detector,
    jwt_detector,
    high_entropy_detector,
)


__all__ = [
    "aws_access_key_detector",
    "openai_key_detector",
    "anthropic_key_detector",
    "github_pat_detector",
    "slack_token_detector",
    "stripe_key_detector",
    "jwt_detector",
    "high_entropy_detector",
    "secrets_detectors",
]
