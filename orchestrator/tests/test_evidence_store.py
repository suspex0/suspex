"""Evidence store unit tests (Part 3, Task 3.1).

record_id determinism, save/load roundtrip byte-identity + atomicity, and
id validation BEFORE any filesystem access (traversal safety).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from suspex.mcp.evidence import store


def _rec(data: dict) -> dict:
    return {"request": {"action": "read", "pid": 1234}, "data": data,
            "tool": "mem_rw", "action": "read"}


# ---------------------------------------------------------------- record_id ----

def test_record_id_deterministic() -> None:
    a = store.record_id(_rec({"hex": "aabb"}), {"action": "read"})
    b = store.record_id(_rec({"hex": "aabb"}), {"action": "read"})
    assert a == b
    assert store.EVIDENCE_ID_RE.fullmatch(a)


def test_record_id_key_order_irrelevant() -> None:
    r1 = {"request": {"action": "read", "pid": 7}, "data": {"hex": "aa", "size": 2}}
    r2 = {"data": {"size": 2, "hex": "aa"}, "request": {"pid": 7, "action": "read"}}
    assert store.record_id(r1, {"action": "read", "pid": 7}) == \
        store.record_id(r2, {"pid": 7, "action": "read"})


def test_record_id_differs_for_different_records() -> None:
    a = store.record_id(_rec({"hex": "aabb"}), {"action": "read"})
    b = store.record_id(_rec({"hex": "aacc"}), {"action": "read"})
    assert a != b


def test_record_id_format() -> None:
    ev = store.record_id(_rec({"hex": "aabb"}), {"action": "read"})
    assert ev.startswith("ev_")
    assert len(ev) == 35  # ev_ + 32 hex
    assert ev == ev.lower()


# -------------------------------------------------------------------- save/load ----

def test_save_load_roundtrip_byte_identical(tmp_path: Path) -> None:
    rec = _rec({"hex": "de" * 256, "addr": "0x1000"})
    ev = store.record_id(rec, {"action": "read"})
    dest = store.save(ev, rec, artifacts_root=tmp_path)
    # Layout: artifacts/evidence/<digest[3:5]>/<digest>.json
    assert dest == tmp_path / "evidence" / ev[3:5] / f"{ev}.json"
    assert dest.exists()
    # Canonical JSON on disk.
    canonical = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    assert dest.read_text(encoding="utf-8") == canonical
    # Atomic write leaves no .tmp behind.
    assert not list(dest.parent.glob("*.tmp"))
    # Roundtrip is byte-identical.
    loaded = store.load(ev, artifacts_root=tmp_path)
    assert loaded == rec
    again = json.dumps(loaded, sort_keys=True, separators=(",", ":"))
    assert again == canonical


def test_save_creates_sharded_dir(tmp_path: Path) -> None:
    ev = store.record_id(_rec({"hex": "aa"}), {})
    store.save(ev, _rec({"hex": "aa"}), artifacts_root=tmp_path)
    shard = tmp_path / "evidence" / ev[3:5]
    assert shard.is_dir()
    assert [p.name for p in shard.iterdir()] == [f"{ev}.json"]


# --------------------------------------------------------------- id validation ----

@pytest.mark.parametrize("bad", ["../../etc", "ev_ZZ", "ev_" + "a" * 31,
                                 "", "../ev_" + "a" * 32, "EV_" + "a" * 32,
                                 "ev_" + "a" * 33])
def test_invalid_ids_rejected_before_filesystem(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("filesystem touched for an invalid id")

    monkeypatch.setattr(Path, "open", _boom, raising=False)
    monkeypatch.setattr(Path, "read_text", _boom, raising=False)
    monkeypatch.setattr(Path, "exists", _boom, raising=False)

    with pytest.raises(store.EvidenceIdError):
        store.load(bad, artifacts_root=tmp_path)
    with pytest.raises(store.EvidenceIdError):
        store.save(bad, {"data": {}}, artifacts_root=tmp_path)
    with pytest.raises(store.EvidenceIdError):
        store.delete(bad, artifacts_root=tmp_path)


def test_load_missing_well_formed_id(tmp_path: Path) -> None:
    ev = "ev_" + "0" * 32
    with pytest.raises(FileNotFoundError):
        store.load(ev, artifacts_root=tmp_path)


def test_delete_and_delete_all(tmp_path: Path) -> None:
    ids = []
    for i in range(3):
        rec = _rec({"hex": f"{i:02x}" * 100})
        ev = store.record_id(rec, {"action": "read", "seq": i})
        store.save(ev, rec, artifacts_root=tmp_path)
        ids.append(ev)
    # A stray file that doesn't match the id regex must survive.
    junk = tmp_path / "evidence" / "zz" / "not-an-evidence-file.json"
    junk.parent.mkdir(parents=True, exist_ok=True)
    junk.write_text("keep me", encoding="utf-8")

    assert store.delete(ids[0], artifacts_root=tmp_path) is True
    assert store.delete(ids[0], artifacts_root=tmp_path) is False
    assert store.delete_all(tmp_path) == 2
    assert junk.exists()
    assert store.delete_all(tmp_path) == 0


def test_continuation_shape() -> None:
    c = store.continuation("ev_" + "a" * 32)
    assert c == {"tool": "knowledge_manage", "action": "evidence_get",
                 "args": {"evidence_id": "ev_" + "a" * 32,
                          "offset": 0, "limit": 64}}


def test_split_detail_normalization() -> None:
    assert store.split_detail(False) == ("complete", False)
    assert store.split_detail(True) == ("complete", True)
    assert store.split_detail("summary") == ("summary", False)
    assert store.split_detail("complete") == ("complete", False)
    assert store.split_detail(None) == ("complete", False)


def test_detail_applies_table() -> None:
    assert store.detail_applies("mem_rw", "read")
    assert store.detail_applies("mem_rw", "disasm")
    assert store.detail_applies("mem_rw", "modules")
    assert not store.detail_applies("mem_rw", "write")
    assert store.detail_applies("dump_manage", "parse")
    assert store.detail_applies("dump_manage", "stack")
    assert not store.detail_applies("dump_manage", "latest")
    assert store.detail_applies("ida_manage", "decompile")
    assert not store.detail_applies("ida_manage", "open")
    assert not store.detail_applies("ida_manage", "actions")
    assert store.detail_applies("ghidra_manage", "decompile")
    assert not store.detail_applies("ghidra_manage", "ghidra_job_status")
