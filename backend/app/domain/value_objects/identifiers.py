"""Value objects for typed identifiers."""

from __future__ import annotations

import ulid


def generate_id() -> str:
    """Generate a new ULID string identifier.

    ULIDs are lexicographically sortable, globally unique, and URL-safe.
    All primary keys in this system use ULIDs.
    """
    return str(ulid.new())
