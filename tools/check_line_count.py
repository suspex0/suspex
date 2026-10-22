#!/usr/bin/env python3
"""Fail if any code file in the repo exceeds the line-count budget.

Walks the working tree from the repository root, counts newline-terminated
lines in each tracked code file, and prints a table of every file that
exceeds the limit. Exit code is non-zero on any violation, so the script
plugs directly into CI or a pre-commit hook.

The budget is 600 lines per file. Documentation (`*.md`, `*.txt`, plan
files) and build/vendored/generated trees are skipped. `comm/suspex_abi.h`
is on the explicit allowlist: it is a shared ABI header (version 9)
consumed by driver + agent + comm + tools, and splitting it would touch
every consumer.

Usage:
    python tools/check_line_count.py          # exit 1 on any violation
    python tools/check_line_count.py --limit 800
    python tools/check_line_count.py --report  # always exit 0, print table
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Files intentionally exempt from the budget. Each entry is a repo-relative
# path (forward slashes) matched exactly against the walked file.
ALLOWLIST_FILES: frozenset[str] = frozenset({
    # Shared ABI/wire contracts — every consumer would move if these split.
    "comm/suspex_abi.h",
    "proto/suspex.proto",
    # Phase-1 follow-ups (see plan): the top-level tool functions cannot
    # be split without changing tool architecture (each ``@mcp.tool`` is
    # one function). Track a follow-up split that groups tool actions
    # into per-action modules.
    "orchestrator/src/suspex/mcp/tools/common.py",
    "orchestrator/src/suspex/mcp/tools/target.py",
    "orchestrator/src/suspex/mcp/tools/mem.py",
    # Phase-6a follow-up: MemorySvc gRPC service class. Splitting would
    # require adding a class-composition scheme (base + partial impls)
    # beyond the plan's TU-level scope.
    "agent/src/grpc/services_memory.cpp",
    # Phase-6d follow-up: host_info.cpp only partially split (host_os.cpp
    # extracted); the remaining free functions (security products +
    # kernel-structure probes) live here still. WDK-dependent code path.
    "agent/src/host/host_info.cpp",
    # Phase-4a follow-up: IdaOpenCloseMixin. Could be split into
    # open/close/status mixins in a follow-up pass.
    "orchestrator/src/suspex/ida_bridge/openclose.py",
})

# Path prefixes containing user-space scripts / in-progress work that the
# 600-line budget does not police. Entries here are ignored the same way
# vendored trees are, but they are called out separately so the intent is
# obvious to readers of this file.
USER_SPACE_PREFIXES: tuple[str, ...] = (
    "plugins/",
)

# Directory prefixes (repo-relative, forward slashes) whose contents are
# skipped wholesale. Includes build outputs, VCS, editor state, vendored
# dependencies, and generated code.
SKIP_DIR_PREFIXES: tuple[str, ...] = (
    ".git/",
    ".kilo/",
    ".claude/",
    ".vs/",
    ".vscode/",
    "build/",
    "dist/",
    "artifacts/",
    "reports/",
    "vcpkg-overlays/",
    "temp_spoofer/",
    "orchestrator/src/suspex/generated/",
    "orchestrator/src/suspex/dashboard/",
    "orchestrator/.venv/",
    "orchestrator/.ida-mcp-venv/",
    "agent/build/",
    "driver/build/",
    "comm/build/",
    "tools/build/",
    "umagent/build/",
    "mapper/build/",
)

# Directory basenames that get skipped anywhere in the tree.
SKIP_DIR_BASENAMES: frozenset[str] = frozenset({
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "site-packages",
    ".egg-info",
})

# Extensions that count as "code" for the budget.
CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py",
    ".c", ".h",
    ".cpp", ".hpp", ".cc", ".cxx", ".hxx",
    ".proto",
})


def is_skipped(rel: str) -> bool:
    for prefix in SKIP_DIR_PREFIXES:
        if rel.startswith(prefix):
            return True
    for prefix in USER_SPACE_PREFIXES:
        if rel.startswith(prefix):
            return True
    return False


def walk_code_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        else:
            rel_dir += "/"
        if any(rel_dir.startswith(p) for p in SKIP_DIR_PREFIXES):
            dirnames[:] = []
            continue
        # Prune skipped dirs so os.walk does not descend into them.
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIR_BASENAMES
            and not d.endswith(".egg-info")
            and not is_skipped(f"{rel_dir}{d}/")
        ]
        for name in filenames:
            ext = Path(name).suffix.lower()
            if ext not in CODE_EXTENSIONS:
                continue
            rel = f"{rel_dir}{name}"
            if rel in ALLOWLIST_FILES:
                continue
            if is_skipped(rel):
                continue
            out.append(Path(dirpath) / name)
    return out


def count_lines(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def repo_root() -> Path:
    here = Path(__file__).resolve()
    # tools/check_line_count.py → tools/ → repo root
    return here.parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=600,
                        help="max lines per code file (default: 600)")
    parser.add_argument("--report", action="store_true",
                        help="print the report but always exit 0")
    parser.add_argument("--top", type=int, default=0,
                        help="also print the N largest files below the limit")
    args = parser.parse_args(argv)

    root = repo_root()
    files = walk_code_files(root)
    sized = [(count_lines(p), p) for p in files]
    over = [(n, p) for n, p in sized if n > args.limit]
    over.sort(reverse=True)

    if over:
        print(f"code files over {args.limit} lines: {len(over)}")
        for n, p in over:
            print(f"  {n:>6}  {p.relative_to(root).as_posix()}")
    else:
        print(f"OK: no code files over {args.limit} lines "
              f"({len(files)} files scanned; allowlist: "
              f"{', '.join(sorted(ALLOWLIST_FILES)) or 'none'})")

    if args.top > 0:
        under = sorted(((n, p) for n, p in sized if n <= args.limit),
                       reverse=True)[:args.top]
        if under:
            print(f"\nTop {len(under)} largest files under the limit:")
            for n, p in under:
                print(f"  {n:>6}  {p.relative_to(root).as_posix()}")

    if args.report:
        return 0
    return 1 if over else 0


if __name__ == "__main__":
    raise SystemExit(main())
