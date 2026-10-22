"""Tests for the value_manage named-constant registry.

Spot-checks a few load-bearing constants and validates the invariants
consumed by `value_manage(action="constants")` enumeration and the
`eval` action's name-resolution fallback.
"""

from __future__ import annotations

import re

from suspex.mcp.value_consts import CATEGORIES, CONST_ENTRIES, CONSTANTS


ALLOWED_CATEGORIES: frozenset[str] = frozenset({
    "memory", "kernel_va", "user_va", "masks", "errno", "units", "nt_status",
})

_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class TestSpotCheck:
    def test_page_size_present(self) -> None:
        assert CONSTANTS["PAGE_SIZE"] == 0x1000

    def test_kuser_shared_data_kernel_present(self) -> None:
        assert CONSTANTS["KUSER_SHARED_DATA_KERNEL"] == 0xFFFFF78000000000

    def test_maxulong64_present(self) -> None:
        assert CONSTANTS["MAXULONG64"] == 0xFFFFFFFFFFFFFFFF

    def test_mb_present(self) -> None:
        assert CONSTANTS["MB"] == 1 << 20

    def test_kb_present(self) -> None:
        assert CONSTANTS["KB"] == 1024

    def test_nt_severity_mask_present(self) -> None:
        assert CONSTANTS["NT_SEVERITY_MASK"] == 0xC0000000


class TestCategories:
    def test_all_seven_category_slugs_covered(self) -> None:
        assert set(CATEGORIES.keys()) == ALLOWED_CATEGORIES

    def test_each_category_nonempty(self) -> None:
        for slug, names in CATEGORIES.items():
            assert names, f"category {slug!r} has no entries"

    def test_categories_match_entries(self) -> None:
        # Every entry's category must appear in CATEGORIES with that name.
        for entry in CONST_ENTRIES:
            assert entry["name"] in CATEGORIES[entry["category"]]


class TestEntryShape:
    def test_every_entry_has_required_keys(self) -> None:
        for entry in CONST_ENTRIES:
            assert "name" in entry
            assert "value" in entry
            assert "category" in entry
            assert "note" in entry

    def test_value_is_int(self) -> None:
        for entry in CONST_ENTRIES:
            # Reject bools even though bool is a subclass of int — a
            # named constant should not be True/False.
            assert type(entry["value"]) is int, \
                f"{entry['name']} value is {type(entry['value']).__name__}, not int"

    def test_category_is_allowed_slug(self) -> None:
        for entry in CONST_ENTRIES:
            assert entry["category"] in ALLOWED_CATEGORIES, \
                f"{entry['name']} has unknown category {entry['category']!r}"

    def test_note_is_nonempty_str(self) -> None:
        for entry in CONST_ENTRIES:
            note = entry["note"]
            assert isinstance(note, str)
            assert note.strip(), f"{entry['name']} has empty note"


class TestNaming:
    def test_no_duplicate_names(self) -> None:
        names = [e["name"] for e in CONST_ENTRIES]
        assert len(names) == len(set(names)), \
            f"duplicate names: {[n for n in names if names.count(n) > 1]}"

    def test_names_upper_snake_case(self) -> None:
        for entry in CONST_ENTRIES:
            name = entry["name"]
            assert _NAME_RE.match(name), \
                f"{name!r} is not UPPER_SNAKE_CASE"


class TestRegistrySize:
    def test_entry_count_above_floor(self) -> None:
        assert len(CONST_ENTRIES) >= 40, \
            f"expected >= 40 entries, got {len(CONST_ENTRIES)}"

    def test_constants_dict_matches_entries(self) -> None:
        assert len(CONSTANTS) == len(CONST_ENTRIES)


class TestCanonicalMask:
    def test_canonical_mask_is_48_bits(self) -> None:
        cm = CONSTANTS["CANONICAL_MASK"]
        assert bin(cm).count("1") == 48, \
            f"CANONICAL_MASK has {bin(cm).count('1')} bits set, expected 48"
