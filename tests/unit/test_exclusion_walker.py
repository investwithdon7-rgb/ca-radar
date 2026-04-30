"""Tests for exclusion_walker — group expansion and cycle detection."""

from __future__ import annotations

from ca_radar.resolver.exclusion_walker import (
    build_user_group_index,
    expand_group_to_users,
    user_in_group,
)
from ca_radar.snapshot.models import Group


def _group(id: str, members: list[str] | None = None, transitive: list[str] | None = None) -> Group:
    return Group(
        id=id,
        display_name=id,
        member_ids=members or [],
        transitive_member_ids=transitive or [],
    )


# ---------------------------------------------------------------------------
# expand_group_to_users
# ---------------------------------------------------------------------------


def test_expand_direct_members() -> None:
    groups = {"g1": _group("g1", members=["u1", "u2"])}
    result = expand_group_to_users("g1", groups)
    assert result == {"u1", "u2"}


def test_expand_uses_transitive_if_available() -> None:
    groups = {"g1": _group("g1", members=["u1"], transitive=["u1", "u2", "u3"])}
    result = expand_group_to_users("g1", groups)
    assert result == {"u1", "u2", "u3"}  # transitive takes priority


def test_expand_nested_group() -> None:
    groups = {
        "g-parent": _group("g-parent", members=["g-child"]),
        "g-child": _group("g-child", members=["u1", "u2"]),
    }
    result = expand_group_to_users("g-parent", groups)
    assert "u1" in result
    assert "u2" in result


def test_expand_three_levels_deep() -> None:
    groups = {
        "g-top": _group("g-top", members=["g-mid"]),
        "g-mid": _group("g-mid", members=["g-bot"]),
        "g-bot": _group("g-bot", members=["u-leaf"]),
    }
    result = expand_group_to_users("g-top", groups)
    assert "u-leaf" in result


def test_expand_missing_group_returns_empty() -> None:
    result = expand_group_to_users("nonexistent", {})
    assert result == set()


def test_expand_cycle_detection() -> None:
    """A → B → A cycle must not loop forever."""
    groups = {
        "g-a": _group("g-a", members=["g-b"]),
        "g-b": _group("g-b", members=["g-a", "u-real"]),
    }
    result = expand_group_to_users("g-a", groups)
    assert "u-real" in result  # real user still returned
    # no infinite loop = test completes


def test_expand_self_reference_cycle() -> None:
    groups = {"g-self": _group("g-self", members=["g-self", "u-ok"])}
    result = expand_group_to_users("g-self", groups)
    assert "u-ok" in result


# ---------------------------------------------------------------------------
# user_in_group
# ---------------------------------------------------------------------------


def test_user_in_group_direct() -> None:
    groups = {"g1": _group("g1", members=["u1"])}
    assert user_in_group("u1", "g1", groups) is True


def test_user_not_in_group() -> None:
    groups = {"g1": _group("g1", members=["u2"])}
    assert user_in_group("u1", "g1", groups) is False


def test_user_in_group_transitive() -> None:
    groups = {
        "g-parent": _group("g-parent", members=["g-child"]),
        "g-child": _group("g-child", members=["u1"]),
    }
    assert user_in_group("u1", "g-parent", groups) is True


def test_membership_cache_is_reused() -> None:
    groups = {"g1": _group("g1", members=["u1"])}
    cache: dict = {}
    user_in_group("u1", "g1", groups, cache)
    assert "g1" in cache
    # Second call hits cache
    assert user_in_group("u1", "g1", groups, cache) is True


# ---------------------------------------------------------------------------
# build_user_group_index
# ---------------------------------------------------------------------------


def test_build_index_simple() -> None:
    groups = {
        "g-a": _group("g-a", members=["u1", "u2"]),
        "g-b": _group("g-b", members=["u2", "u3"]),
    }
    index = build_user_group_index(groups)
    assert "g-a" in index["u1"]
    assert "g-a" in index["u2"]
    assert "g-b" in index["u2"]
    assert "g-b" in index["u3"]


def test_build_index_nested_groups() -> None:
    groups = {
        "g-parent": _group("g-parent", members=["g-child"]),
        "g-child": _group("g-child", members=["u1"]),
    }
    index = build_user_group_index(groups)
    # u1 should appear in both g-parent and g-child
    assert "g-child" in index.get("u1", set())
    assert "g-parent" in index.get("u1", set())
