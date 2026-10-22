"""Plugin discovery/validation/subprocess-execution tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

from suspex.config import SuspexConfig
from suspex.plugins import (PluginError, discover, file_result, plugin_dir,
                            resolve_plugins_dir, run_plugin, validate_params)
from suspex.findings import FindingsLedger
from suspex.session import Session

EXAMPLE_YAML = """
name: tplug
description: test plugin
target: any
params:
  message:
    type: str
    default: hi
  repeat:
    type: int
    default: 2
  mode:
    type: str
    default: plain
    enum: ["plain", "async"]
"""

EXAMPLE_RUN = """
def run(sdk, params):
    return {"ok": True, "echo": params["message"] * params["repeat"], "mode": params["mode"]}
"""

ASYNC_RUN = """
async def run(sdk, params):
    return {"ok": True, "mode": params["mode"]}
"""


def _make_plugin(tmp_path, run_text=EXAMPLE_RUN) -> str:
    d = tmp_path / "tplug"
    d.mkdir()
    (d / "plugin.yaml").write_text(EXAMPLE_YAML, encoding="utf-8")
    (d / "run.py").write_text(run_text, encoding="utf-8")
    return str(d)


def _cfg_with_plugins(tmp_path) -> SuspexConfig:
    cfg = SuspexConfig()
    cfg.plugins.dir = str(tmp_path)
    return cfg


def test_validate_params_defaults_and_errors() -> None:
    schema = yaml.safe_load(EXAMPLE_YAML)["params"]
    clean = validate_params(schema, {})
    assert clean == {"message": "hi", "repeat": 2, "mode": "plain"}
    clean = validate_params(schema, {"message": "yo"})
    assert clean["message"] == "yo"
    with pytest.raises(PluginError, match="required"):
        validate_params({"x": {"type": "int", "required": True}}, {})
    with pytest.raises(PluginError, match="must be int"):
        validate_params({"x": {"type": "int"}}, {"x": "nope"})
    with pytest.raises(PluginError, match="one of"):
        validate_params(schema, {"mode": "bogus"})
    with pytest.raises(PluginError, match="unknown params"):
        validate_params(schema, {"nope": 1})


def test_discover_and_resolve(tmp_path) -> None:
    _make_plugin(tmp_path)
    (tmp_path / "_skipme").mkdir()  # underscore dirs are not plugins
    cfg = _cfg_with_plugins(tmp_path)
    metas = discover(cfg)
    assert [m.name for m in metas] == ["tplug"]
    assert metas[0].params["repeat"]["default"] == 2
    assert resolve_plugins_dir(cfg) == tmp_path


def test_plugin_dir_rejects_traversal(tmp_path) -> None:
    cfg = _cfg_with_plugins(tmp_path)
    with pytest.raises(PluginError, match="invalid"):
        plugin_dir(cfg, "../secrets")
    with pytest.raises(PluginError, match="unknown plugin"):
        plugin_dir(cfg, "ghost")


async def test_run_plugin_subprocess(tmp_path) -> None:
    _make_plugin(tmp_path)
    cfg = _cfg_with_plugins(tmp_path)
    session = Session(SuspexConfig())  # no views: offline plugin still runs
    result = await run_plugin(cfg, session, None, "", "tplug",
                              {"message": "ab", "repeat": 3})
    assert result["echo"] == "ababab"


async def test_run_plugin_async_run_fn(tmp_path) -> None:
    _make_plugin(tmp_path, ASYNC_RUN)
    cfg = _cfg_with_plugins(tmp_path)
    session = Session(SuspexConfig())
    result = await run_plugin(cfg, session, None, "", "tplug", {"mode": "async"})
    assert result["mode"] == "async"


async def test_run_plugin_param_error_fails_fast(tmp_path) -> None:
    _make_plugin(tmp_path)
    cfg = _cfg_with_plugins(tmp_path)
    session = Session(SuspexConfig())
    with pytest.raises(PluginError, match="must be int"):
        await run_plugin(cfg, session, None, "", "tplug", {"repeat": "many"})


async def test_run_plugin_unknown_name(tmp_path) -> None:
    cfg = _cfg_with_plugins(tmp_path)
    session = Session(SuspexConfig())
    with pytest.raises(PluginError, match="unknown plugin"):
        await run_plugin(cfg, session, None, "", "ghost", {})


async def test_run_plugin_target_view_required(tmp_path) -> None:
    d = tmp_path / "strict"
    d.mkdir()
    (d / "plugin.yaml").write_text(
        "name: strict\ntarget: kernel\nparams: {}\n", encoding="utf-8")
    (d / "run.py").write_text("def run(sdk, params):\n    return {}\n", encoding="utf-8")
    cfg = _cfg_with_plugins(tmp_path)
    session = Session(SuspexConfig())
    with pytest.raises(PluginError, match="kernel"):
        await run_plugin(cfg, session, None, "", "strict", {})


async def test_file_result_records_finding(tmp_path) -> None:
    led = FindingsLedger(tmp_path / "f.db")
    filed = file_result(led, "", "tplug", {"ok": True, "severity": "warning",
                                           "summary": "s", "data": 1})
    assert filed["severity"] == "warning"
    rows = [f.__dict__ for f in led.list_findings(None, None)]
    assert rows[0]["refs"] == "plugin:tplug"
    assert rows[0]["severity"] == "warning"
    led.close()


def test_repo_plugins_pack_resolves() -> None:
    # the real repo layout must auto-resolve (cfg.plugins.dir unset)
    d = resolve_plugins_dir(SuspexConfig())
    assert (Path(d) / "_patterns.yaml").is_file()
    assert (Path(d) / "sigscan" / "run.py").is_file()


def test_scripts_user_overrides_repo_pack(tmp_path, monkeypatch) -> None:
    # a same-named plugin in scripts_user shadows the shipped pack
    from suspex import plugins as plugins_mod

    pack = tmp_path / "plugins"
    personal = tmp_path / "scripts_user"
    for root, desc in ((pack, "from pack"), (personal, "test plugin")):
        (root / "tplug").mkdir(parents=True)
        (root / "tplug" / "plugin.yaml").write_text(
            EXAMPLE_YAML.replace("test plugin", desc), encoding="utf-8")
        (root / "tplug" / "run.py").write_text(EXAMPLE_RUN, encoding="utf-8")
    monkeypatch.setattr(plugins_mod, "plugin_roots", lambda cfg: [personal, pack])

    metas = [m for m in plugins_mod.discover(SuspexConfig()) if m.name == "tplug"]
    assert len(metas) == 1
    assert metas[0].description == "test plugin"
    assert Path(metas[0].path) == personal / "tplug"
    assert plugins_mod.plugin_dir(SuspexConfig(), "tplug") == personal / "tplug"
