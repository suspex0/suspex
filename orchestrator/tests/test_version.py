"""Version-skew test: pyproject, SERVER_VERSION, and the latest CHANGELOG
heading must agree.

Formats in play:
- pyproject ``project.version``: "X.Y.Z" (PEP 440, three components)
- ``SERVER_VERSION`` (server.py): "X.Y.Z-YYYY-MM-DD" — the date suffix is
  a build stamp, so only the X.Y.Z prefix is compared
- CHANGELOG headings: "## vX.Y" (two components for recent releases;
  older ones use vX.Y.Z)

All three normalize to an int tuple with trailing zeros stripped before
comparison, so 0.29.0 == 0.29.
"""

from __future__ import annotations

import re
import tomllib

import _catalog


def _norm(version: str) -> tuple[int, ...]:
    parts = tuple(int(p) for p in version.split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def test_versions_in_sync() -> None:
    pyproject = tomllib.loads(_catalog.PYPROJECT_PATH.read_text(encoding="utf-8"))
    pyproject_version = pyproject["project"]["version"]

    server_src = _catalog.SERVER_PY_PATH.read_text(encoding="utf-8")
    match = re.search(r'SERVER_VERSION\s*=\s*"([^"]+)"', server_src)
    assert match, "SERVER_VERSION not found in server.py"
    server_version = re.sub(r"-\d{4}-\d{2}-\d{2}$", "", match.group(1))

    changelog = _catalog.CHANGELOG_PATH.read_text(encoding="utf-8")
    heading = re.search(r"^## v?(\d+(?:\.\d+)*)", changelog, re.M)
    assert heading, "no '## vX.Y.Z' heading found in CHANGELOG.md"
    changelog_version = heading.group(1)

    assert _norm(pyproject_version) == _norm(server_version), (
        f"pyproject {pyproject_version} != SERVER_VERSION {server_version}"
    )
    assert _norm(server_version) == _norm(changelog_version), (
        f"SERVER_VERSION {server_version} != CHANGELOG {changelog_version}"
    )
