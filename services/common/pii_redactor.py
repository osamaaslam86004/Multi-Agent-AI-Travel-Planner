"""
PII Redaction utility for sanitizing user queries, tool outputs, and telemetry streams.
Redacts emails, phone numbers, credit card numbers, and government identification numbers.
"""

import re

# Regex patterns for common PII formats
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_REGEX = re.compile(
    r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PASSPORT_REGEX = re.compile(r"\b[A-PR-WYa-pr-wy][0-9]{7,8}\b")


def redact_pii(text: str | None) -> str:
    """
    Sanitizes untrusted text by stripping sensitive PII before provider processing
    or persistent stream logging.
    """
    if not text:
        return ""

    sanitized = str(text)
    sanitized = EMAIL_REGEX.sub("[REDACTED_EMAIL]", sanitized)
    sanitized = SSN_REGEX.sub("[REDACTED_SSN]", sanitized)
    sanitized = PHONE_REGEX.sub("[REDACTED_PHONE]", sanitized)
    sanitized = CREDIT_CARD_REGEX.sub("[REDACTED_CARD]", sanitized)
    sanitized = PASSPORT_REGEX.sub("[REDACTED_ID]", sanitized)

    return sanitized


def sanitize_tool_output(text: str | None, max_length: int = 3000) -> str:
    """
    Sanitizes tool/MCP text output by redacting PII, stripping URLs/HTML,
    and enforcing token blowup max character bounds.
    """
    if not text:
        return ""

    # Redact PII
    cleaned = redact_pii(text)

    # Strip markdown and plain HTTP links to mitigate indirect prompt injection
    cleaned = re.sub(r"\[([^\]]+)\]\(https?://[^\)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"https?://\S+", "[LINK_REMOVED]", cleaned)

    # Strip HTML tags
    cleaned = re.sub(r"<[^>]+>", "", cleaned)

    # Enforce maximum character boundary
    if len(cleaned) > max_length:
        cleaned = (
            cleaned[:max_length]
            + f"\n...[Output truncated to {max_length} characters to prevent token blowup]"
        )

    return cleaned
