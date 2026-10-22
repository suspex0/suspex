"""Tests for _suspex_driver_probe.

Uses a scripted fake AgentClient to exercise the probe's decision tree
without a live target. Covers the four verdicts:
  * loaded
  * service_registered_not_started
  * file_present_no_service
  * absent_clean
  * orphan_service
"""
from __future__ import annotations

import asyncio

import pytest

from suspex.mcp._suspex_driver_probe import (
    _resolve_image_path,
    _verdict,
    probe_suspex_driver,
)


# ---------------------------------------------------------------- Fake client --

class _FakeClient:
    """Minimal scripted AgentClient: canned reg_enum/reg_get + file_list_dir/hash
    responses driven by dict tables."""

    def __init__(self, *, service_key_present: bool,
                 service_values: dict | None = None,
                 files_by_dir: dict[str, list[dict]] | None = None,
                 hashes: dict[str, dict] | None = None):
        self._svc_present = service_key_present
        self._svc_values = service_values or {}
        self._dirs = files_by_dir or {}
        self._hashes = hashes or {}

    async def reg_enum(self, hive, subkey, *, want_subkeys=True, want_values=True,
                       wow64_32=False, impersonate=""):
        if hive == "HKLM" and subkey.endswith("SuspexDrv"):
            if not self._svc_present:
                raise RuntimeError("RegOpenKeyExW gle=2 (FILE_NOT_FOUND)")
            return {"subkeys": [],
                    "values": [{"name": k, "type": 0, "size": 0}
                                for k in self._svc_values]}
        raise RuntimeError(f"unexpected reg_enum({subkey!r})")

    async def reg_get(self, hive, subkey, value, *, wow64_32=False,
                      impersonate="", raw_hex=False):
        # v0.17 A-3: the probe passes ``raw_hex=True`` to keep the wide
        # response shape (needed for `str` + `qword` field access). This
        # mock ignores the flag and always returns the wide shape.
        v = self._svc_values.get(value)
        if v is None:
            raise RuntimeError("value not found gle=2")
        if isinstance(v, int):
            return {"type": 4, "size": 4, "hex": "", "str": "",
                    "qword": v, "multi_sz": []}
        return {"type": 1, "size": len(v), "hex": "", "str": v,
                "qword": 0, "multi_sz": []}

    async def file_list_dir(self, path, recursive=False, max_entries=2000):
        return list(self._dirs.get(path, []))

    async def file_hash(self, path):
        h = self._hashes.get(path)
        if h is None:
            raise RuntimeError(f"hash gle=2 for {path}")
        return h


# ---------------------------------------------------------------- Unit checks --

def test_resolve_image_path_ntpath():
    assert _resolve_image_path(r"\??\C:\suspex\suspex_driver.sys") \
           == r"C:\suspex\suspex_driver.sys"


def test_resolve_image_path_systemroot():
    assert _resolve_image_path(r"\SystemRoot\System32\drivers\foo.sys") \
           == r"C:\Windows\System32\drivers\foo.sys"


def test_resolve_image_path_plain():
    assert _resolve_image_path(r"C:\dev\suspex.sys") == r"C:\dev\suspex.sys"


def test_verdict_loaded():
    v, hint = _verdict(True, {"registered": True}, {"present": True})
    assert v == "loaded"


def test_verdict_service_registered_not_started():
    v, _ = _verdict(False, {"registered": True}, {"present": True})
    assert v == "service_registered_not_started"


def test_verdict_orphan_service():
    v, _ = _verdict(False, {"registered": True, "image_path": r"\??\C:\missing.sys"},
                     {"present": False})
    assert v == "orphan_service"


def test_verdict_file_present_no_service():
    v, _ = _verdict(False, {"registered": False}, {"present": True})
    assert v == "file_present_no_service"


def test_verdict_absent_clean():
    v, _ = _verdict(False, {"registered": False}, {"present": False})
    assert v == "absent_clean"


# ---------------------------------------------------------------- E2E via fake --

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if not hasattr(
        asyncio, "run") else asyncio.run(coro)


def test_probe_absent_clean():
    c = _FakeClient(service_key_present=False)
    result = _run(probe_suspex_driver(c, driver_state="DRIVER_ABSENT"))
    assert result["verdict"] == "absent_clean"
    assert result["service"]["registered"] is False
    assert result["file"]["present"] is False


def test_probe_service_registered_not_started():
    svc = {
        "ImagePath": r"\??\C:\suspex\suspex_driver.sys",
        "Start": 3,
        "Type": 1,
        "DisplayName": "Suspex0 kernel driver",
    }
    files = {
        r"C:\suspex": [
            {"name": "suspex_driver.sys", "dir": False, "size": 65536},
            {"name": "suspex_agent.exe", "dir": False, "size": 1000000},
        ],
    }
    hashes = {r"C:\suspex\suspex_driver.sys": {"sha256": "abc" * 21 + "d", "size": 65536}}
    c = _FakeClient(service_key_present=True, service_values=svc,
                     files_by_dir=files, hashes=hashes)
    result = _run(probe_suspex_driver(c, driver_state="DRIVER_ABSENT"))
    assert result["verdict"] == "service_registered_not_started"
    assert result["service"]["registered"] is True
    assert result["service"]["start_type"] == 3
    assert "DEMAND" in result["service"]["start_type_decoded"]
    assert result["file"]["present"] is True
    assert result["file"]["sha256"].startswith("abc")


def test_probe_orphan_service():
    svc = {"ImagePath": r"\??\C:\gone\suspex_driver.sys", "Start": 3, "Type": 1}
    # No files anywhere.
    c = _FakeClient(service_key_present=True, service_values=svc,
                     files_by_dir={})
    result = _run(probe_suspex_driver(c, driver_state="DRIVER_ABSENT"))
    assert result["verdict"] == "orphan_service"
    assert result["file"]["present"] is False


def test_probe_loaded_state_reflected():
    svc = {"ImagePath": r"\??\C:\suspex\suspex_driver.sys", "Start": 3, "Type": 1}
    files = {r"C:\suspex": [{"name": "suspex_driver.sys", "dir": False, "size": 65536}]}
    c = _FakeClient(service_key_present=True, service_values=svc, files_by_dir=files)
    result = _run(probe_suspex_driver(c, driver_state="DRIVER_SERVICE"))
    assert result["loaded"] is True
    assert result["verdict"] == "loaded"
