"""
SQL Injection payload provider and database error signatures.

Provides non-destructive payloads for detecting error-based and boolean-based
SQL injection, as well as signatures to identify database error messages in responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from payloads.base import Payload, PayloadProvider


@dataclass(frozen=True)
class SqliBooleanPair:
    """A pair of payloads where one evaluates to TRUE and the other evaluates to FALSE."""

    true_payload: str
    false_payload: str
    context: str  # "string", "numeric", etc.
    description: str


# Database error signatures mapped by database engine.
# Designed to be matched case-insensitively.
DATABASE_ERROR_PATTERNS: dict[str, list[str]] = {
    "sqlite": [
        r"sqlite3\.OperationalError",
        r"SQLITE_ERROR",
        r"SequelizeDatabaseError",
        r"near \".*\": syntax error",
        r"near '.*': syntax error",
        r"unrecognized token:",
        r"SQL logic error or missing database",
    ],
    "mysql": [
        r"You have an error in your SQL syntax",
        r"check the manual that corresponds to your MySQL server version",
        r"check the manual that corresponds to your MariaDB server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
    ],
    "postgresql": [
        r"syntax error at or near",
        r"psycopg2\.errors\.",
        r"org\.postgresql\.util\.PSQLException",
        r"pg_query\(\): Query failed",
        r"ERROR:\s+parser:\s+parse error at or near",
    ],
    "mssql": [
        r"Unclosed quotation mark after the character string",
        r"Line \d+: Incorrect syntax near",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"System\.Data\.SqlClient\.SqlException",
    ],
    "oracle": [
        r"ORA-00933: SQL command not properly ended",
        r"ORA-00936: missing expression",
        r"ORA-01756: quoted string not properly terminated",
        r"quoted string not properly terminated",
    ],
    "generic": [
        r"SQL syntax error",
        r"syntax error in query expression",
        r"Unexpected end of command in statement",
        r"Syntax error in SQL statement",
    ],
}


def detect_sql_error(text: str) -> Optional[tuple[str, str]]:
    """
    Search text for known database error patterns.
    Returns (db_engine, matched_pattern) if found, else None.
    """
    for engine, patterns in DATABASE_ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return engine, match.group(0)
    return None


class SqliPayloadProvider(PayloadProvider):
    """Provides curated non-destructive SQL injection payloads."""

    def __init__(self) -> None:
        self._error_payloads = [
            Payload(
                value="'",
                strategy="error_based",
                description="Single quote string delimiter",
            ),
            Payload(
                value="''",
                strategy="error_based",
                description="Double single-quote escape probe",
            ),
            Payload(
                value='"',
                strategy="error_based",
                description="Double quote string delimiter",
            ),
            Payload(
                value="')",
                strategy="error_based",
                description="Closing parenthesis with quote delimiter",
            ),
            Payload(
                value="';",
                strategy="error_based",
                description="Quote with query terminator semicolon",
            ),
            Payload(
                value="\\",
                strategy="error_based",
                description="Backslash escape character",
            ),
        ]

        self._boolean_pairs = [
            SqliBooleanPair(
                true_payload="' OR '1'='1",
                false_payload="' AND '1'='2",
                context="string",
                description="Standard string literal boolean comparison",
            ),
            SqliBooleanPair(
                true_payload="' OR ''='",
                false_payload="' AND ''='x",
                context="string",
                description="Empty string comparison",
            ),
            SqliBooleanPair(
                true_payload=" OR 1=1",
                false_payload=" AND 1=2",
                context="numeric",
                description="Numeric literal boolean comparison",
            ),
            SqliBooleanPair(
                true_payload=") OR (1=1",
                false_payload=") AND (1=2",
                context="parenthesis",
                description="Parenthesized clause boolean comparison",
            ),
        ]

    def get_payloads(self) -> list[Payload]:
        """Return error-based payloads."""
        return list(self._error_payloads)

    def get_boolean_pairs(self) -> list[SqliBooleanPair]:
        """Return boolean differential test pairs."""
        return list(self._boolean_pairs)
