"""
Reusable response comparison utilities.

Scanners that rely on differential analysis (e.g. "does the response change
when I send a different Origin / a different auth token / a payload?") should
use these helpers rather than ad-hoc `if response != baseline` checks, which
produce excessive false positives.

Every comparison function returns a structured observation object rather than
a bare boolean, so scanners can weigh multiple weak signals into a single
confidence score instead of treating any one difference as proof of a
vulnerability.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from typing import Any, Optional

from core.http_client import HttpResponse


@dataclass
class ComparisonResult:
    equal: bool
    detail: str
    metadata: dict[str, Any]


def compare_status_codes(baseline: HttpResponse, test: HttpResponse) -> ComparisonResult:
    equal = baseline.status_code == test.status_code
    return ComparisonResult(
        equal=equal,
        detail=f"baseline={baseline.status_code} test={test.status_code}",
        metadata={"baseline_status": baseline.status_code, "test_status": test.status_code},
    )


def compare_response_length(
    baseline: HttpResponse, test: HttpResponse, tolerance_ratio: float = 0.02
) -> ComparisonResult:
    base_len = len(baseline.body)
    test_len = len(test.body)
    if base_len == 0 and test_len == 0:
        return ComparisonResult(True, "both empty", {"baseline_length": 0, "test_length": 0})

    diff_ratio = abs(base_len - test_len) / max(base_len, test_len, 1)
    equal = diff_ratio <= tolerance_ratio
    return ComparisonResult(
        equal=equal,
        detail=f"baseline_length={base_len} test_length={test_len} diff_ratio={diff_ratio:.4f}",
        metadata={
            "baseline_length": base_len,
            "test_length": test_len,
            "diff_ratio": diff_ratio,
        },
    )


def compare_body_similarity(baseline: HttpResponse, test: HttpResponse) -> ComparisonResult:
    """Uses a sequence matcher ratio (0.0 - 1.0) rather than exact equality."""
    ratio = difflib.SequenceMatcher(None, baseline.body, test.body).ratio()
    return ComparisonResult(
        equal=ratio > 0.98,
        detail=f"similarity_ratio={ratio:.4f}",
        metadata={"similarity_ratio": ratio},
    )


def compare_response_time(
    baseline: HttpResponse, test: HttpResponse, threshold_seconds: float = 3.0
) -> ComparisonResult:
    delta = test.elapsed_seconds - baseline.elapsed_seconds
    equal = delta < threshold_seconds
    return ComparisonResult(
        equal=equal,
        detail=f"baseline={baseline.elapsed_seconds:.3f}s test={test.elapsed_seconds:.3f}s delta={delta:.3f}s",
        metadata={
            "baseline_seconds": baseline.elapsed_seconds,
            "test_seconds": test.elapsed_seconds,
            "delta_seconds": delta,
        },
    )


def compare_headers(
    baseline: HttpResponse, test: HttpResponse, header_names: Optional[list[str]] = None
) -> ComparisonResult:
    """Compare specific headers (case-insensitive); if none given, compares all."""

    def _lower_keys(headers: dict[str, str]) -> dict[str, str]:
        return {k.lower(): v for k, v in headers.items()}

    base_headers = _lower_keys(baseline.headers)
    test_headers = _lower_keys(test.headers)

    names = [h.lower() for h in header_names] if header_names else set(base_headers) | set(test_headers)

    differences = {}
    for name in names:
        b_val = base_headers.get(name)
        t_val = test_headers.get(name)
        if b_val != t_val:
            differences[name] = {"baseline": b_val, "test": t_val}

    return ComparisonResult(
        equal=len(differences) == 0,
        detail=f"{len(differences)} header(s) differ" if differences else "no header differences",
        metadata={"differences": differences},
    )


def compare_json_structure(baseline: HttpResponse, test: HttpResponse) -> ComparisonResult:
    """Compares the *shape* (keys/types), not values, of two JSON responses."""

    def _shape(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _shape(v) for k, v in sorted(value.items())}
        if isinstance(value, list):
            return [_shape(value[0])] if value else []
        return type(value).__name__

    try:
        base_shape = _shape(json.loads(baseline.body)) if baseline.body else None
        test_shape = _shape(json.loads(test.body)) if test.body else None
    except (json.JSONDecodeError, ValueError):
        return ComparisonResult(
            equal=False, detail="one or both responses were not valid JSON", metadata={}
        )

    equal = base_shape == test_shape
    return ComparisonResult(
        equal=equal,
        detail="same JSON shape" if equal else "different JSON shape",
        metadata={"baseline_shape": base_shape, "test_shape": test_shape},
    )
