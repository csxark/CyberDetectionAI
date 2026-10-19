"""Redaction engine for SentinelAI.

Removes credentials, API keys, JWTs, private keys, passwords, and PII
before log content is passed to external models, SSE streams, or telemetries.
Supports consistent reversible pseudonyms within an investigation.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import ClassVar

from sentinel_config.guardrails import DEFAULT_GUARDRAILS, RedactionConfig


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


@dataclass
class Redactor:
    """Scans and masks sensitive patterns with consistent pseudonym generation."""

    config: RedactionConfig = field(default_factory=lambda: DEFAULT_GUARDRAILS.redaction)
    _pseudonym_map: dict[str, str] = field(default_factory=dict)
    _reverse_map: dict[str, str] = field(default_factory=dict)
    _counter: dict[str, int] = field(default_factory=lambda: Counter())

    # Precompiled regex patterns
    JWT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"
    )
    API_KEY_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:api[_-]?key|token|secret|auth[_-]?token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"
    )
    PRIVATE_KEY_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    )
    PASSWORD_IN_URL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(https?://[^\s:]+:)([^@\s]+)(@[^\s]+)"
    )
    EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    )
    CREDIT_CARD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    )

    def _get_pseudonym(self, category: str, original_val: str) -> str:
        """Get or create consistent pseudonym if pseudonym_consistency is enabled."""
        if not self.config.pseudonym_consistency:
            return f"[REDACTED_{category.upper()}]"

        key = f"{category}:{original_val}"
        if key not in self._pseudonym_map:
            self._counter[category] += 1
            idx = self._counter[category]
            pseudo = f"[REDACTED_{category.upper()}_{idx:03d}]"
            self._pseudonym_map[key] = pseudo
            self._reverse_map[pseudo] = original_val
        return self._pseudonym_map[key]

    def redact(self, text: str) -> str:
        """Scan text and replace sensitive tokens according to config."""
        if not text:
            return text

        result = text

        # 1. Private keys
        if self.config.redact_private_keys:
            def _repl_privkey(match: re.Match[str]) -> str:
                return self._get_pseudonym("PRIVATE_KEY", match.group(0))
            result = self.PRIVATE_KEY_PATTERN.sub(_repl_privkey, result)

        # 2. JWTs
        if self.config.redact_jwts:
            def _repl_jwt(match: re.Match[str]) -> str:
                return self._get_pseudonym("JWT", match.group(0))
            result = self.JWT_PATTERN.sub(_repl_jwt, result)

        # 3. Passwords in URLs
        if self.config.redact_passwords_in_urls:
            def _repl_pw_url(match: re.Match[str]) -> str:
                prefix, secret, suffix = match.groups()
                pseudo = self._get_pseudonym("PASSWORD", secret)
                return f"{prefix}{pseudo}{suffix}"
            result = self.PASSWORD_IN_URL_PATTERN.sub(_repl_pw_url, result)

        # 4. API keys / secrets
        if self.config.redact_api_keys:
            def _repl_key(match: re.Match[str]) -> str:
                whole = match.group(0)
                secret = match.group(1)
                pseudo = self._get_pseudonym("API_KEY", secret)
                return whole.replace(secret, pseudo)
            result = self.API_KEY_PATTERN.sub(_repl_key, result)

        # 5. Credit cards
        if self.config.redact_credit_cards:
            def _repl_cc(match: re.Match[str]) -> str:
                return self._get_pseudonym("CREDIT_CARD", match.group(0))
            result = self.CREDIT_CARD_PATTERN.sub(_repl_cc, result)

        # 6. Emails
        if self.config.redact_emails:
            def _repl_email(match: re.Match[str]) -> str:
                return self._get_pseudonym("EMAIL", match.group(0))
            result = self.EMAIL_PATTERN.sub(_repl_email, result)

        # 7. High entropy tokens (optional per token check in whitespace separated words)
        if self.config.redact_high_entropy_strings:
            words = result.split(" ")
            new_words = []
            for word in words:
                clean_word = word.strip(".,;:\"'()[]{}")
                if len(clean_word) >= 24 and _shannon_entropy(clean_word) >= self.config.high_entropy_threshold:
                    pseudo = self._get_pseudonym("HIGH_ENTROPY", clean_word)
                    new_words.append(word.replace(clean_word, pseudo))
                else:
                    new_words.append(word)
            result = " ".join(new_words)

        return result

    def get_reverse_mapping(self) -> dict[str, str]:
        """Return the pseudonym to original mapping for authorized reversibility."""
        return dict(self._reverse_map)
