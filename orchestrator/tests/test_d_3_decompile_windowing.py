"""D-3: `decompile_function` windowing + annotations toggle.

The vendored plugin emits per-line ``/* line: N, address: 0x… */``
annotations — measured at 30-40% wire-token overhead across a 35 KB
decompilation. v0.17 D-3 flips the default (annotations off) and adds
address-centered windowing + a byte-cap truncation flag.

Pure logic in :func:`ida_shim_ergo.apply_decompile_window` and
:func:`strip_decompile_annotations`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import (  # noqa: E402
    apply_decompile_window,
    strip_decompile_annotations,
)


def _synth_decomp(start_ea: int, n_lines: int = 20) -> str:
    """Return a synthetic annotated decompilation for the tests.

    Line 0 gets the function-start ea; each subsequent line gets an ea
    four bytes further along. Every line carries the vendored plugin's
    ``/* line: N, address: 0x… */`` trailer so the annotation stripper
    and address-window finder both have something to key on.
    """
    lines: list[str] = []
    for i in range(n_lines):
        ea = start_ea + (i * 4)
        lines.append(
            f"  v{i} = call_stub({i});  /* line: {i}, address: 0x{ea:X} */"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# strip_decompile_annotations
# --------------------------------------------------------------------------- #


def test_d_3_strip_annotations_removes_trailer():
    src = "  x = 1;  /* line: 3, address: 0x140010A0 */"
    out = strip_decompile_annotations(src)
    assert out == "  x = 1;"
    assert "line:" not in out
    assert "address:" not in out


def test_d_3_strip_annotations_preserves_indent():
    src = (
        "int f() {\n"
        "    if (x) {  /* line: 1, address: 0x1000 */\n"
        "        y = 1;  /* line: 2, address: 0x1004 */\n"
        "    }\n"
        "}\n"
    )
    out = strip_decompile_annotations(src)
    # Indentation on structural lines preserved.
    assert "    if (x) {" in out
    assert "        y = 1;" in out
    assert "/* line:" not in out


def test_d_3_strip_annotations_on_empty_text_returns_empty():
    assert strip_decompile_annotations("") == ""


# --------------------------------------------------------------------------- #
# apply_decompile_window — annotations toggle
# --------------------------------------------------------------------------- #


def test_d_3_annotations_false_strips_line_ea_comments():
    text = _synth_decomp(0x1400_0000, n_lines=5)
    assert "line:" in text  # baseline

    out = apply_decompile_window(text, annotations=False)
    assert out["annotations"] is False
    assert "line:" not in out["text"]
    assert "address:" not in out["text"]
    # The stripped text is shorter than the annotated original.
    assert out["byte_count"] < len(text)


def test_d_3_annotations_true_preserves_line_ea_comments():
    text = _synth_decomp(0x1400_0000, n_lines=5)
    out = apply_decompile_window(text, annotations=True)
    assert out["annotations"] is True
    assert "line:" in out["text"]
    assert "address:" in out["text"]


# --------------------------------------------------------------------------- #
# apply_decompile_window — around_address windowing
# --------------------------------------------------------------------------- #


def test_d_3_around_address_narrows_output():
    # A 40-line function; ask for a 5-line window around a mid-function ea.
    text = _synth_decomp(0x1400_0000, n_lines=40)
    # Line 20 is at 0x14000050 (20 * 4).
    out = apply_decompile_window(
        text,
        annotations=True,  # keep annotations so the window finder has data
        around_address="0x14000050",
        window_lines=3,
    )
    assert out["windowed"] is True
    # window_lines=3 above and below -> 7 lines total.
    line_count = len(out["text"].split("\n"))
    assert line_count <= 7
    # The target line is included.
    assert "0x14000050" in out["text"]
    # window_span is populated with first/last line indices.
    assert out["window_span"] is not None
    assert "first_line" in out["window_span"]
    assert "last_line" in out["window_span"]


def test_d_3_around_without_annotations_returns_full():
    # If the caller has already stripped annotations, the window finder has
    # nothing to key on — the transformer degrades to the full stripped text
    # (windowed=False) rather than guessing.
    stripped = strip_decompile_annotations(_synth_decomp(0x1400_0000, n_lines=40))
    out = apply_decompile_window(
        stripped,
        annotations=False,
        around_address="0x14000050",
        window_lines=3,
    )
    assert out["windowed"] is False
    assert out["window_span"] is None
    # Full text returned.
    assert out["byte_count"] == len(stripped)


def test_d_3_around_target_before_function_start_still_windows_from_top():
    # Ask for an ea BEFORE the function start — we should NOT crash and
    # should return the full stripped text as fallback.
    text = _synth_decomp(0x1400_1000, n_lines=10)
    out = apply_decompile_window(
        text,
        annotations=True,
        around_address="0x14000000",  # below the function
        window_lines=3,
    )
    # No line's ea <= target, so windowed=False and full text returned.
    assert out["windowed"] is False


# --------------------------------------------------------------------------- #
# apply_decompile_window — max_bytes truncation
# --------------------------------------------------------------------------- #


def test_d_3_max_bytes_truncates_and_flags():
    text = _synth_decomp(0x1400_0000, n_lines=100)
    out = apply_decompile_window(text, annotations=True, max_bytes=200)
    assert out["truncated"] is True
    assert out["byte_count"] == 200
    assert len(out["text"]) == 200


def test_d_3_max_bytes_zero_disables_truncation():
    text = _synth_decomp(0x1400_0000, n_lines=5)
    out = apply_decompile_window(text, annotations=True, max_bytes=0)
    assert out["truncated"] is False
    assert out["byte_count"] == len(text)


# --------------------------------------------------------------------------- #
# apply_decompile_window — response envelope shape
# --------------------------------------------------------------------------- #


def test_d_3_envelope_carries_expected_fields():
    out = apply_decompile_window("hello world", annotations=True)
    for f in ("text", "annotations", "windowed", "window_span",
              "truncated", "byte_count"):
        assert f in out


def test_d_3_none_text_returns_empty_envelope():
    # Defensive — the vendored plugin can return an empty response envelope
    # in odd states; the transformer treats None as an empty string.
    out = apply_decompile_window(None, annotations=False)
    assert out["text"] == ""
    assert out["byte_count"] == 0
    assert out["truncated"] is False


def test_d_3_window_then_strip_annotations_order():
    # window_lines=1 -> 3 lines around the target; annotations then get
    # stripped from those 3 lines.
    text = _synth_decomp(0x1400_0000, n_lines=10)
    out = apply_decompile_window(
        text,
        annotations=False,
        around_address="0x1400000C",  # line 3 (3*4=0xC)
        window_lines=1,
    )
    assert out["windowed"] is True
    assert "line:" not in out["text"]  # annotations stripped after window
    assert "address:" not in out["text"]
    # Three lines back in the window.
    assert out["text"].count("\n") <= 2
