"""Recursive group-membership expansion with cycle detection.

CA policy includes/excludes reference group object IDs.  A user matches
a group reference if they are a *transitive* member — i.e. a direct member
of the group, or a member of any nested group.

This module resolves that transitive membership from the snapshot data
(which already contains `transitive_member_ids` from Graph's
`/groups/{id}/transitiveMembers` call where available, and falls back to
manual recursion over `member_ids` when transitive data is missing).

Cycle detection is mandatory: some tenants have circular group nesting
via dynamic membership rules, which would otherwise cause infinite loops.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ca_radar.snapshot.models import Group

log = logging.getLogger(__name__)


def expand_group_to_users(
    group_id: str,
    groups_by_id: dict[str, Group],
    visited: frozenset[str] | None = None,
) -> set[str]:
    """Return the set of user IDs that are transitive members of *group_id*.

    Uses `transitive_member_ids` when populated (Graph pre-computed), otherwise
    walks `member_ids` recursively.  Cycle detection via *visited* set.

    Args:
        group_id:      The group to expand.
        groups_by_id:  Mapping from group ID to Group model.
        visited:       Groups already on the current recursion path (cycle guard).

    Returns:
        Set of user-like object IDs (not group IDs) that belong to this group.
    """
    if visited is None:
        visited = frozenset()

    if group_id in visited:
        log.warning(
            "Cycle detected in group membership: %s is already on path %s", group_id, visited
        )
        return set()

    group = groups_by_id.get(group_id)
    if group is None:
        log.debug("Group %s not found in snapshot — skipping", group_id)
        return set()

    # Fast path: Graph already returned transitive members
    if group.transitive_member_ids:
        return set(group.transitive_member_ids)

    # Slow path: manual recursion over direct members
    visited = visited | {group_id}
    user_ids: set[str] = set()

    for member_id in group.member_ids:
        if member_id in groups_by_id:
            # It's a nested group — recurse
            nested = expand_group_to_users(member_id, groups_by_id, visited)
            user_ids.update(nested)
        else:
            # Treat as a user (or service principal) ID
            user_ids.add(member_id)

    return user_ids


def user_in_group(
    user_id: str,
    group_id: str,
    groups_by_id: dict[str, Group],
    _membership_cache: dict[str, set[str]] | None = None,
) -> bool:
    """Return True if *user_id* is a transitive member of *group_id*.

    Pass a *_membership_cache* dict across calls to avoid repeated expansion
    of the same group (important for coverage matrix computation).
    """
    if _membership_cache is None:
        _membership_cache = {}

    if group_id not in _membership_cache:
        _membership_cache[group_id] = expand_group_to_users(group_id, groups_by_id)

    return user_id in _membership_cache[group_id]


def build_user_group_index(
    groups_by_id: dict[str, Group],
) -> dict[str, set[str]]:
    """Pre-compute a reverse index: user_id → set of group IDs they belong to.

    This is O(groups × members) but is computed once at resolver init time
    and then used for O(1) per-user lookups.
    """
    index: dict[str, set[str]] = {}
    # Cache expanded sets so nested groups aren't expanded multiple times.
    expanded_cache: dict[str, set[str]] = {}

    for group_id in groups_by_id:
        if group_id not in expanded_cache:
            expanded_cache[group_id] = expand_group_to_users(group_id, groups_by_id)
        for user_id in expanded_cache[group_id]:
            index.setdefault(user_id, set()).add(group_id)

    return index
