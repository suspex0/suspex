"""Persistent machine registry — purpose / note / trust metadata + endpoint
credentials for target machines (v0.30).

``artifacts/targets.json`` stores machine entries so boxes can be added at
runtime (``target_manage(action='machines_register')``) without editing the
YAML config or restarting the orchestrator. YAML ``machines:`` stays the
reviewed, committed config; the registry is the runtime layer:

- registry-owned aliases (not in YAML) carry full endpoint/credential data
  and merge into ``cfg.machines`` at load and at register time, so
  ``Session`` view resolution works unchanged;
- YAML aliases can only receive *metadata* overlays (purpose/note/trust/
  tags/operator) — endpoints and tokens of reviewed config are never
  overridden unless ``force=True`` (explicit shadow);
- the reserved alias ``default`` annotates the implicit primary machine
  (the YAML ``target:`` block, which has no alias of its own).

Tokens may be stored as ``${ENV_VAR}`` and are expanded with
``os.path.expandvars`` when merged into config. They are NEVER echoed in
any response (``token_set: true`` instead).
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Any

from .config import TRUST_LEVELS, MachineConfig, SuspexConfig

REGISTRY_FILENAME = "targets.json"
REGISTRY_VERSION = 1
DEFAULT_ALIAS = "default"

_METADATA_FIELDS = ("trust", "purpose", "note", "operator", "tags")


def _norm_trust(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in TRUST_LEVELS else "untrusted"


def _validate_alias(alias: str) -> str:
    a = str(alias or "").strip()
    if not a:
        raise ValueError("machine alias must be non-empty")
    if any(c.isspace() for c in a):
        raise ValueError(f"machine alias {a!r} must not contain whitespace")
    if len(a) > 64:
        raise ValueError(f"machine alias {a!r} too long (max 64)")
    return a


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _clone_machine(m: MachineConfig) -> MachineConfig:
    return copy.deepcopy(m)


class MachineRegistry:
    """Read/write layer over ``artifacts/targets.json`` + the YAML config."""

    def __init__(self, cfg: SuspexConfig, path: Path) -> None:
        self.cfg = cfg
        self.path = Path(path)
        # alias (lowercased) -> raw entry dict as persisted
        self._entries: dict[str, dict[str, Any]] = {}
        # aliases defined by the reviewed YAML config (never silently
        # shadowed by registry endpoint/credential data)
        self._yaml_aliases = {str(a).lower() for a in (cfg.machines or {})}
        # pristine YAML MachineConfigs — restoring one after a force-shadow
        # is removed (registry mutations happen on merged copies otherwise)
        self._yaml_snapshot: dict[str, MachineConfig] = {
            str(a): _clone_machine(m) for a, m in (cfg.machines or {}).items()}

    # ------------------------------------------------------------ loading ----

    @classmethod
    def load(cls, cfg: SuspexConfig) -> "MachineRegistry":
        """Load the registry file (missing = empty) and merge it into
        ``cfg.machines`` so view resolution works unchanged."""
        try:
            base = Path(cfg.artifacts_dir())
        except Exception:
            base = Path("artifacts")
        reg = cls(cfg, base / REGISTRY_FILENAME)
        reg._read()
        reg.merge_into_cfg()
        return reg

    def _read(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        machines = raw.get("machines") if isinstance(raw, dict) else None
        if not isinstance(machines, dict):
            return
        for alias, entry in machines.items():
            if isinstance(entry, dict):
                self._entries[str(alias).lower()] = dict(entry)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": REGISTRY_VERSION,
                   "machines": {a: e for a, e in sorted(self._entries.items())}}
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    # ------------------------------------------------------------- config ----

    def merge_into_cfg(self) -> None:
        """Fold registry entries into ``cfg.machines``.

        Registry-owned aliases become full MachineConfig entries (tokens
        env-expanded). YAML aliases get metadata overlays only — endpoint
        fields land there solely for entries registered with force=True
        (explicit shadow)."""
        for lower, ent in self._entries.items():
            alias = str(ent.get("alias") or lower)
            mcfg = self._find_machine(alias)
            is_yaml = lower in self._yaml_aliases
            if is_yaml:
                if mcfg is None:
                    continue
                self._apply_metadata(mcfg, ent)
                if ent.get("shadow"):
                    self._apply_endpoints(mcfg, ent)
                continue
            if mcfg is None:
                mcfg = MachineConfig()
                self.cfg.machines[alias] = mcfg
            self._apply_metadata(mcfg, ent)
            self._apply_endpoints(mcfg, ent)

    def _find_machine(self, alias: str) -> MachineConfig | None:
        machines = getattr(self.cfg, "machines", None) or {}
        if alias in machines:
            return machines[alias]
        low = str(alias).lower()
        for a, m in machines.items():
            if str(a).lower() == low:
                return m
        return None

    @staticmethod
    def _apply_metadata(mcfg: MachineConfig, ent: dict[str, Any]) -> None:
        for f in _METADATA_FIELDS:
            if ent.get(f) not in (None, "", []):
                setattr(mcfg, f, ent[f])

    @staticmethod
    def _apply_endpoints(mcfg: MachineConfig, ent: dict[str, Any]) -> None:
        if ent.get("host"):
            mcfg.host = os.path.expandvars(str(ent["host"]))
        if ent.get("token"):
            mcfg.token = os.path.expandvars(str(ent["token"]))
        if ent.get("kernel_port"):
            mcfg.kernel_port = int(ent["kernel_port"])
            mcfg.views.pop("kernel", None)
        if ent.get("user_port"):
            mcfg.user_port = int(ent["user_port"])
            mcfg.views.pop("user", None)

    # ------------------------------------------------------------ writing ----

    def register(self, alias: str, *, host: str = "", kernel_port: int = 0,
                 user_port: int = 0, token: str = "", trust: str = "",
                 purpose: str = "", note: str = "", operator: str = "",
                 tags: list[str] | None = None,
                 force: bool = False) -> dict[str, Any]:
        """Add (or replace) a machine entry. Refuses to shadow a YAML
        alias's endpoints/credentials unless ``force=True``."""
        alias = _validate_alias(alias)
        lower = alias.lower()
        has_endpoints = bool(host or kernel_port or user_port or token)
        if lower == DEFAULT_ALIAS and has_endpoints:
            raise ValueError(
                "'default' annotates the implicit primary machine — "
                "metadata only (endpoints come from the YAML target: block)")
        shadow = False
        if lower in self._yaml_aliases and has_endpoints:
            if not force:
                raise ValueError(
                    f"machine {alias!r} is defined by the reviewed YAML "
                    "config — metadata only without force=true")
            shadow = True
        entry: dict[str, Any] = {
            "alias": alias,
            "trust": _norm_trust(trust),
            "purpose": str(purpose or ""),
            "note": str(note or ""),
            "operator": str(operator or ""),
            "tags": [str(t) for t in (tags or []) if str(t).strip()],
            "registered_at": _now(),
        }
        if shadow:
            entry["shadow"] = True
        vals = {"host": host, "kernel_port": kernel_port,
                "user_port": user_port, "token": token}
        for k, v in vals.items():
            if v:
                entry[k] = v
        self._entries[lower] = entry
        self._save()
        self.merge_into_cfg()
        return self.describe(alias)

    def set(self, alias: str, *, host: str | None = None,
            kernel_port: int | None = None, user_port: int | None = None,
            token: str | None = None, trust: str | None = None,
            purpose: str | None = None, note: str | None = None,
            operator: str | None = None, tags: list[str] | None = None,
            force: bool = False) -> dict[str, Any]:
        """Partial update. YAML aliases accept metadata fields only
        (endpoint/credential fields need ``force=True``)."""
        alias = _validate_alias(alias)
        lower = alias.lower()
        ent = dict(self._entries.get(lower) or {"alias": alias})
        endpoint_wanted = any(
            v not in (None, "", 0) for v in (host, kernel_port, user_port, token))
        if lower == DEFAULT_ALIAS and endpoint_wanted:
            raise ValueError(
                "'default' annotates the implicit primary machine — "
                "metadata only")
        if lower in self._yaml_aliases and endpoint_wanted and not force:
            raise ValueError(
                f"machine {alias!r} is defined by the reviewed YAML "
                "config — metadata only without force=true")
        for k, v in (("host", host), ("token", token),
                     ("kernel_port", kernel_port), ("user_port", user_port)):
            if v not in (None, "", 0):
                ent[k] = v
        for k, v in (("trust", _norm_trust(trust) if trust is not None else None),
                     ("purpose", purpose), ("note", note), ("operator", operator)):
            if v is not None:
                ent[k] = v
        if tags is not None:
            ent["tags"] = [str(t) for t in tags if str(t).strip()]
        if lower in self._yaml_aliases and endpoint_wanted:
            ent["shadow"] = True
        ent.setdefault("registered_at", _now())
        ent["alias"] = alias
        self._entries[lower] = ent
        self._save()
        self.merge_into_cfg()
        return self.describe(alias)

    def unregister(self, alias: str, force: bool = False) -> bool:
        """Drop a registry entry. YAML aliases keep their endpoints (they
        live in the YAML file) — only the metadata overlay is removed;
        a force-registered shadow needs ``force=True`` to remove."""
        alias = _validate_alias(alias)
        lower = alias.lower()
        if lower not in self._entries:
            return False
        ent = self._entries[lower]
        if lower in self._yaml_aliases:
            if ent.get("shadow") and not force:
                raise ValueError(
                    f"machine {alias!r} shadows the YAML config — "
                    "force=true to remove the shadow")
            self._entries.pop(lower, None)
            if ent.get("shadow"):
                # restore the pristine reviewed-config MachineConfig
                snap = next((s for a, s in self._yaml_snapshot.items()
                             if str(a).lower() == lower), None)
                if snap is not None:
                    machines = getattr(self.cfg, "machines", None) or {}
                    for a in [a for a in machines if str(a).lower() == lower]:
                        machines[a] = _clone_machine(snap)
            else:
                mcfg = self._find_machine(alias)
                if mcfg is not None:
                    for f in _METADATA_FIELDS:
                        setattr(mcfg, f, [] if f == "tags" else "")
            self._save()
            return True
        self._entries.pop(lower, None)
        machines = getattr(self.cfg, "machines", None)
        if isinstance(machines, dict):
            for a in [a for a in machines if str(a).lower() == lower]:
                machines.pop(a, None)
        self._save()
        return True

    # ------------------------------------------------------------ reading ----

    def entry(self, alias: str) -> dict[str, Any] | None:
        return self._entries.get(str(alias or "").strip().lower())

    def all(self) -> dict[str, dict[str, Any]]:
        return {str(e.get("alias") or k): dict(e)
                for k, e in sorted(self._entries.items())}

    def trust_for(self, machine_label: str) -> str:
        """Trust level for a machine label — registry entry, then YAML
        ``machines:`` metadata, then the ``default`` overlay for the
        implicit machine, then ``untrusted`` (fail-safe default)."""
        key = str(machine_label or "").strip().lower()
        ent = self._entries.get(key)
        if ent is not None:
            return _norm_trust(ent.get("trust"))
        mcfg = self._find_machine(key)
        if mcfg is not None and getattr(mcfg, "trust", ""):
            return _norm_trust(mcfg.trust)
        if key not in self._yaml_aliases:
            ent = self._entries.get(DEFAULT_ALIAS)
            if ent is not None:
                return _norm_trust(ent.get("trust"))
        return "untrusted"

    def describe(self, alias: str,
                 cfg: SuspexConfig | None = None) -> dict[str, Any] | None:
        """The ``machine_info`` block for *alias* — never contains the
        token (``token_set`` flag instead)."""
        cfg = cfg or self.cfg
        key = str(alias or "").strip()
        if not key:
            return None
        lower = key.lower()
        ent = self._entries.get(lower) or {}
        mcfg = self._find_machine(key)
        if ent.get("alias"):
            key = str(ent["alias"])
        # The implicit machine (learned label like a computer name) has no
        # entry of its own — the 'default' overlay supplies metadata, but
        # never endpoints (those come from the YAML target: block).
        meta = ent
        if not meta and mcfg is None and lower != DEFAULT_ALIAS:
            meta = self._entries.get(DEFAULT_ALIAS) or {}
        trust = _norm_trust(ent.get("trust") or meta.get("trust")
                            or getattr(mcfg, "trust", ""))
        endpoints: dict[str, str] = {}
        if isinstance(mcfg, MachineConfig):
            for kind in (list(mcfg.views) or ["kernel", "user"]):
                try:
                    tc = mcfg.view(kind)
                except Exception:
                    continue
                if tc.host:
                    endpoints[str(kind)] = f"{tc.host}:{tc.port}"
        elif lower == DEFAULT_ALIAS:
            if getattr(cfg.target, "host", ""):
                endpoints["kernel"] = f"{cfg.target.host}:{cfg.target.port}"
            ut = (getattr(cfg, "targets", None) or {}).get("user")
            if ut is not None and getattr(ut, "host", ""):
                endpoints["user"] = f"{ut.host}:{ut.port}"
        elif ent.get("host"):
            for kind, pkey in (("kernel", "kernel_port"), ("user", "user_port")):
                if ent.get(pkey):
                    endpoints[kind] = (f"{os.path.expandvars(str(ent['host']))}"
                                       f":{int(ent[pkey])}")
        if ent.get("shadow") and isinstance(mcfg, MachineConfig):
            for kind, tc in (mcfg.views or {}).items():
                if getattr(tc, "host", ""):
                    endpoints[str(kind)] = f"{tc.host}:{tc.port}"
        info: dict[str, Any] = {
            "machine": key,
            "trust": trust,
            "purpose": str(ent.get("purpose") or meta.get("purpose")
                           or getattr(mcfg, "purpose", "") or ""),
            "note": str(ent.get("note") or meta.get("note")
                        or getattr(mcfg, "note", "") or ""),
            "operator": str(ent.get("operator") or meta.get("operator")
                            or getattr(mcfg, "operator", "") or ""),
            "tags": [str(t) for t in (ent.get("tags") or meta.get("tags")
                                      or getattr(mcfg, "tags", None) or [])],
            "endpoints": endpoints,
            "source": ("registry" if ent else
                       ("yaml" if mcfg is not None else
                        ("default" if lower == DEFAULT_ALIAS else "adhoc"))),
            "token_set": bool(ent.get("token") or
                              (isinstance(mcfg, MachineConfig)
                               and getattr(mcfg, "token", ""))),
        }
        if ent.get("registered_at"):
            info["registered_at"] = str(ent["registered_at"])
        return info
