"""
Cross-Site Scripting (XSS) payload provider.

Provides benign, non-destructive probe payloads containing unique canary tokens
to detect unescaped reflection in various HTML/JavaScript contexts.
"""

from __future__ import annotations

import html
import uuid
from dataclasses import dataclass
from typing import Optional

from payloads.base import Payload, PayloadProvider


@dataclass(frozen=True)
class XssProbe:
    """An XSS probe instance with a unique canary to track reflection."""

    canary: str
    payload_template: str  # Template containing "{canary}"
    context: str  # "html_tag", "attribute_dq", "attribute_sq", "script_breakout"
    description: str

    @property
    def rendered_payload(self) -> str:
        return self.payload_template.format(canary=self.canary)


def is_reflected_unescaped(canary: str, response_body: str) -> bool:
    """
    Check if the canary and its enclosing dangerous characters appear unescaped in response_body.
    If the canary only appears HTML-entity-encoded (e.g. &lt;xss_... or &quot;), returns False.
    """
    if canary not in response_body:
        return False

    raw_indicators = [
        f"<xss_{canary}",
        f"<{canary}",
        f'"><xss_{canary}',
        f"'><xss_{canary}",
        f"</script><xss_{canary}",
        f">{canary}",
        f'"{canary}"',
        f"'{canary}'",
    ]

    # If any raw tag/attribute breakout is present unescaped
    if any(raw in response_body for raw in raw_indicators):
        return True

    # Check for escaped versions
    escaped_indicators = [
        f"&lt;xss_{canary}",
        f"&lt;{canary}",
        f"&#60;xss_{canary}",
        f"&#x3c;xss_{canary}",
    ]
    if any(esc in response_body for esc in escaped_indicators):
        return False

    # Default fallback: if canary appears with '<' nearby
    return f"<xss_{canary}" in response_body


class XssPayloadProvider(PayloadProvider):
    """Provides benign XSS canary probes for various injection contexts."""

    TEMPLATES = [
        (
            "<xss_{canary}>",
            "html_tag",
            "Direct HTML tag context injection",
        ),
        (
            '"><xss_{canary}>',
            "attribute_dq",
            "Attribute breakout via double quote",
        ),
        (
            "'><xss_{canary}>",
            "attribute_sq",
            "Attribute breakout via single quote",
        ),
        (
            "</script><xss_{canary}>",
            "script_breakout",
            "Script tag breakout context",
        ),
    ]

    def generate_probes(self) -> list[XssProbe]:
        """Generate a fresh set of probes with unique canary tokens."""
        token = uuid.uuid4().hex[:8]
        return [
            XssProbe(
                canary=f"{token}_{idx}",
                payload_template=template,
                context=context,
                description=desc,
            )
            for idx, (template, context, desc) in enumerate(self.TEMPLATES)
        ]

    def get_payloads(self) -> list[Payload]:
        """Return static representative payloads implementing PayloadProvider interface."""
        return [
            Payload(
                value=template.format(canary="canary"),
                strategy=context,
                description=desc,
            )
            for template, context, desc in self.TEMPLATES
        ]
