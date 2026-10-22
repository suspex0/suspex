"""Plugin discovery, param validation, and subprocess execution (phase 2).

A plugin is `plugins/<name>/` (the tracked pack) or `scripts_user/<name>/`
(local overlay) with:
  plugin.yaml  name, description, target (kernel|user|any), params schema
  run.py       def run(sdk, params) -> dict   (sync or async)

Execution happens in a subprocess (`python -m suspex.plugin_runner`) so
plugins can block or crash without taking the MCP server down; the SDK is
built inside the runner from a view descriptor passed on stdin. Results are
captured as JSON and auto-filed as a finding with evidence.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


class PluginError(RuntimeError):
    pass


@dataclass
class PluginMeta:
    name: str
    description: str
    target: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)


def plugin_roots(cfg: Any) -> list[Path]:
    """Plugin directories to scan, highest precedence first.

    `cfg.plugins.dir` when set (CWD-relative) is the only root. Otherwise the
    repo-root `scripts_user` (personal overlay, gitignored) is scanned before
    the tracked `plugins` pack, so a local plugin shadows a shipped one of the
    same name.
    """
    configured = getattr(getattr(cfg, "plugins", None), "dir", "")
    if configured:
        p = Path(configured)
        if p.is_dir():
            return [p]
        raise PluginError(f"plugins dir not found: {p}")
    repo = Path(__file__).resolve().parents[3]
    roots = [repo / d for d in ("scripts_user", "plugins") if (repo / d).is_dir()]
    if not roots:
        raise PluginError("no plugin directory found (expected plugins/ or "
                          "scripts_user/; set plugins.dir in config)")
    return roots


def resolve_plugins_dir(cfg: Any) -> Path:
    """Primary plugin dir: `cfg.plugins.dir` if set, else the tracked
    repo-root `plugins` pack (falling back to `scripts_user`)."""
    roots = plugin_roots(cfg)
    repo = Path(__file__).resolve().parents[3]
    for root in roots:
        if root == repo / "plugins":
            return root
    return roots[0]


_BAD_MANIFESTS: dict[str, str] = {}


def discover(cfg: Any) -> list[PluginMeta]:
    by_name: dict[str, PluginMeta] = {}
    _BAD_MANIFESTS.clear()
    # lowest precedence first so `scripts_user` overrides the shipped pack
    for root in reversed(plugin_roots(cfg)):
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name.startswith("_"):
                continue
            try:
                meta = load_meta(d)
            except yaml.YAMLError as exc:
                # v0.9.4: one plugin with a malformed manifest previously
                # crashed the whole `script_manage list` — yaml.safe_load
                # raised ScannerError/MarkedYAMLError and the exception
                # propagated to the tool caller. Skip the plugin, record
                # the parse error, and continue so the caller still sees
                # every other valid manifest.
                _BAD_MANIFESTS[d.name] = f"YAML parse error: {exc}"
                continue
            except Exception as exc:
                _BAD_MANIFESTS[d.name] = f"{type(exc).__name__}: {exc}"
                continue
            if meta is not None:
                by_name[meta.name] = meta
    return [by_name[k] for k in sorted(by_name)]


def bad_manifests() -> dict[str, str]:
    """Copy of the last discover() pass's parse-error map — plugin name → err.

    Empty when every manifest loaded cleanly. Useful for surfacing skipped
    plugins in `script_manage list` without breaking the happy path.
    """
    return dict(_BAD_MANIFESTS)


def plugin_dir(cfg: Any, name: str) -> Path:
    if name.startswith("_") or "/" in name or "\\" in name or ".." in name:
        raise PluginError(f"invalid plugin name {name!r}")
    for root in plugin_roots(cfg):
        d = root / name
        if (d / "plugin.yaml").is_file():
            return d
    raise PluginError(f"unknown plugin {name!r} (plugins: "
                      f"{[m.name for m in discover(cfg)]})")


def load_meta(d: Path) -> PluginMeta | None:
    yaml_path = d / "plugin.yaml"
    if not yaml_path.is_file():
        return None
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    return PluginMeta(
        name=str(raw.get("name") or d.name),
        description=str(raw.get("description") or ""),
        target=str(raw.get("target") or "any"),
        path=str(d),
        params=dict(raw.get("params") or {}),
    )


def validate_params(schema: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    """Minimal schema subset: type, required, default, enum, description."""
    types = {"str": str, "int": int, "float": (int, float), "bool": bool,
             "list": list, "dict": dict}
    out: dict[str, Any] = {}
    for key, spec in schema.items():
        spec = spec if isinstance(spec, dict) else {"type": spec}
        value = params.get(key)
        if value is None:
            if "default" in spec:
                out[key] = spec["default"]
            elif spec.get("required"):
                raise PluginError(f"missing required param {key!r}")
            continue
        want = types.get(str(spec.get("type", "str")))
        if want and not isinstance(value, want):
            raise PluginError(f"param {key!r} must be {spec.get('type')}, "
                              f"got {type(value).__name__}")
        enum = spec.get("enum")
        if enum and value not in enum:
            raise PluginError(f"param {key!r} must be one of {enum}")
        out[key] = value
    extra = set(params) - set(schema)
    if extra:
        raise PluginError(f"unknown params: {sorted(extra)}")
    return out


def _view_descriptors(session: Any) -> dict[str, dict[str, Any]]:
    views: dict[str, dict[str, Any]] = {}
    for name, client in session.clients.items():
        label = (session.machine_label(name)
                 if hasattr(session, "machine_label") else {})
        views[name] = {
            "host": client.host,
            "port": client.port,
            "token": client.token,
            "timeout_ms": int(client.timeout_ms),
            "machine": label.get("machine") or name,
            "computer_name": label.get("computer_name") or "",
        }
    return views


def _symbols_descriptor(cfg: Any) -> dict[str, Any]:
    sym = getattr(cfg, "symbols", None)
    cache = getattr(cfg.artifacts, "pdb_cache", "artifacts/symbols") if cfg else ""
    if cfg is not None and hasattr(cfg, "pdb_cache_dir"):
        cache = str(cfg.pdb_cache_dir())
    elif cache and not Path(cache).is_absolute():
        cache = str(Path(__file__).resolve().parents[2] / cache)
    return {
        "cache_dir": str(cache),
        "allow_download": bool(getattr(sym, "allow_download", True)),
        "servers": list(getattr(sym, "servers", []) or []),
    }


async def run_plugin(cfg: Any, session: Any, ledger: Any, session_id: str, name: str,
                     params: dict[str, Any], timeout_s: float = 300.0) -> dict[str, Any]:
    meta = load_meta(plugin_dir(cfg, name))
    if meta is None:
        raise PluginError(f"plugin {name!r} has no plugin.yaml")
    clean = validate_params(meta.params, params)

    required = meta.target
    if required in ("kernel", "user"):
        # Multi-machine: the requirement is a view KIND present on some
        # connected machine — keys are '<machine>.<kind>' now.
        if not any(session.view_kind_of(k) == required
                   for k in session.clients):
            raise PluginError(f"plugin {name!r} requires the {required!r} view (connect it first)")

    nt_build = 0
    try:
        nt_build = int((await session.require_client("kernel").status()).get("os_build") or 0)
    except Exception:
        pass

    payload = {
        "views": _view_descriptors(session),
        "nt_build": nt_build,
        "ledger": str(ledger.db_path) if ledger is not None else "",
        "session_id": session_id,
        "symbols": _symbols_descriptor(cfg),
        # Canonical artifact root from the orchestrator config — plugins
        # used to guess Path.cwd()/artifacts, which moved with the launch
        # cwd. Empty string is fine: SuspexSDK falls back to cwd/artifacts.
        "artifacts_dir": str(cfg.artifacts_dir()) if hasattr(cfg, "artifacts_dir") else "",
    }
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "suspex.plugin_runner",
        "--plugin-dir", str(Path(meta.path)),
        "--params-json", json.dumps(clean),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input=json.dumps(payload).encode()), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise PluginError(f"plugin {name!r} timed out after {timeout_s:.0f}s")

    try:
        envelope = json.loads(out.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        raise PluginError(f"plugin {name!r} produced no JSON result "
                          f"(exit {proc.returncode}); stderr tail: "
                          f"{err.decode('utf-8', 'replace')[-400:]}")
    if not envelope.get("ok"):
        raise PluginError(f"plugin {name!r} failed: {envelope.get('error')}")
    return envelope.get("result", {})


def file_result(ledger: Any, session_id: str, name: str, result: dict[str, Any]) -> dict[str, Any]:
    """Auto-file a plugin result as a finding with evidence."""
    severity = str(result.get("severity") or "info")
    summary = str(result.get("summary") or "")
    sid = session_id or ledger.start_session("plugins")
    fid = ledger.record(sid, severity, f"plugin: {name}", summary, refs=f"plugin:{name}")
    eid = ledger.add_evidence(fid, "plugin_result", json.dumps(result, indent=2, default=str))
    return {"finding_id": fid, "evidence_id": eid, "session_id": sid, "severity": severity}


def meta_dict(meta: PluginMeta) -> dict[str, Any]:
    return asdict(meta)
