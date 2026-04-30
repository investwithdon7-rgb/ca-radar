"""OData pagination helpers.

Graph returns paginated collections via @odata.nextLink.
These helpers accumulate all pages into a single list.
"""

from __future__ import annotations

from typing import Any

NEXT_LINK_KEY = "@odata.nextLink"
VALUE_KEY = "value"


def extract_value(response_json: dict[str, Any]) -> list[Any]:
    """Return the 'value' array from a Graph collection response."""
    return list(response_json.get(VALUE_KEY, []))


def extract_next_link(response_json: dict[str, Any]) -> str | None:
    """Return the next-page URL, or None if this is the last page."""
    return response_json.get(NEXT_LINK_KEY)


def is_paginated(response_json: dict[str, Any]) -> bool:
    return NEXT_LINK_KEY in response_json
