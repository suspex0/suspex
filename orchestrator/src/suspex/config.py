"""YAML-driven orchestrator configuration with safe defaults."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PRIMARY_TARGET = "kernel"  # the default (kernel agent) view name

# v0.30 machine trust levels (registry / machines: metadata). Ordered —
# an actuator on a machine is allowed when its trust is >= the configured
# security.min_trust_actuator. "untrusted" is the fail-safe default and
# also disables the gate entirely when used as the threshold.
TRUST_LEVELS: dict[str, int] = {
    "untrusted": 0,
    "restricted": 1,
    "lab": 2,
}


def _project_root() -> Path:
    """Repo root in a source checkout (``orchestrator/src/suspex/config.py``
    -> ``parents[2]`` is ``orchestrator/``, its parent the repo root),
    else the process cwd for installed-package layouts.

    v0.27: the anchor for every RELATIVE artifact path — a bare
    ``dir: artifacts`` used to resolve against whatever cwd the server
    launched with, so dumps written under ``<repo>/artifacts`` were
    invisible to a boot running from ``orchestrator/`` (and produced
    the two-store drift v0.18 documented for findings.db).
    """
    pkg = Path(__file__).resolve()
    try:
        orch = pkg.parents[2]          # .../orchestrator
        if orch.name == "orchestrator" and (orch / "src" / "suspex").is_dir():
            return orch.parent
    except IndexError:
        pass
    return Path.cwd()


@dataclass
class TargetConfig:
    host: str = "127.0.0.1"
    port: int = 50074
    token: str = ""
    connect_timeout_ms: int = 10000
    # Cap on gRPC calls in flight per AgentClient. Prevents a fan-out loop
    # (bulk region reads, IAT walks, plugin sweeps) from stampeding the
    # agent's IOCTL thread pool; the AgentClient enforces this via a
    # semaphore around each _call. Absent-in-yaml stays at the default.
    max_inflight: int = 16
    # v0.28: NIC lease flap (.167/.196) — extra hosts tried, in order,
    # when the configured host fails the pre-flight TCP probe. The
    # last host that connected is remembered in-memory and retried
    # first on the next connect. Empty list = probe only the configured
    # host (the historical behavior).
    alt_hosts: list[str] = field(default_factory=list)


@dataclass
class MachineConfig:
    """One lab machine's view endpoints, from the ``machines:`` block:

        machines:
          lab2:
            host: 10.0.2.15            # shared by both views
            token: secret              # shared default
            kernel_port: 50099
            user_port: 50075
            # or per-view overrides:
            kernel: {port: 50099, token: other}
            user:   {host: 10.0.2.16, port: 50075}

    Both shapes expand to ``targets['lab2.kernel']`` / ``targets['lab2.user']``
    at load time; ``machine_for_endpoint`` maps a connected host:port back
    to the machine alias so view keys stay human-stable when IPs move.
    """
    host: str = ""
    token: str = ""
    kernel_port: int = 50099
    user_port: int = 50075
    connect_timeout_ms: int = 10000
    max_inflight: int = 16
    # v0.28: fallback hosts for lease flap (see TargetConfig.alt_hosts).
    alt_hosts: list[str] = field(default_factory=list)
    views: dict[str, "TargetConfig"] = field(default_factory=dict)
    # v0.30: machine metadata. YAML `machines:` may carry these directly;
    # the runtime registry (registry.py) overlays them for YAML aliases
    # and owns them for registry-registered machines. `trust` is one of
    # TRUST_LEVELS — gates actuator verbs via security.min_trust_actuator.
    purpose: str = ""
    note: str = ""
    trust: str = "untrusted"
    operator: str = ""
    tags: list[str] = field(default_factory=list)

    def view(self, kind: str) -> "TargetConfig":
        """Effective TargetConfig for view *kind* — explicit per-view
        override wins; machine-level host/token fill fields left at the
        dataclass default."""
        tc = self.views.get(kind)
        if tc is not None:
            dflt = TargetConfig()
            if self.host and tc.host == dflt.host:
                tc = dataclasses.replace(tc, host=self.host)
            if self.token and tc.token == dflt.token:
                tc = dataclasses.replace(tc, token=self.token)
            if self.alt_hosts and not tc.alt_hosts:
                tc = dataclasses.replace(tc, alt_hosts=list(self.alt_hosts))
            return tc
        port = self.kernel_port if kind == "kernel" else self.user_port
        return TargetConfig(host=self.host, port=port, token=self.token,
                            connect_timeout_ms=self.connect_timeout_ms,
                            max_inflight=self.max_inflight,
                            alt_hosts=list(self.alt_hosts))


@dataclass
class SecurityConfig:
    authorized_targets: list[str] = field(default_factory=lambda: ["127.0.0.0/8"])
    allow_delete: bool = False
    allow_driver_unload: bool = True
    allow_driver_load: bool = True
    max_transfer_mb: int = 512
    max_mem_read_mb: int = 8
    # v11: Device.Ioctl is an actuator — a bad IOCTL can bugcheck the
    # target. Off by default; flip on in the lab config when the device
    # under test is known-good.
    allow_ioctl_send: bool = False
    # v11: event subscribe registers PsSet*NotifyRoutine callbacks in the
    # driver — kernel-visible state. Gated like driver_load.
    allow_event_stream: bool = False
    # v15: Exec.CallFunction runs attacker-chosen code in target context —
    # the strongest actuator in the stack. Off by default.
    allow_function_call: bool = False
    # v0.30: machine-trust gate for actuator verbs (ioctl send,
    # driver_load/unload, boot_recover, kill_process, exec call). A
    # machine whose trust (registry / machines: metadata) is below this
    # threshold gets the actuator refused unless the call passes
    # force=true. "untrusted" (default) = no gating. See TRUST_LEVELS.
    min_trust_actuator: str = "untrusted"


@dataclass
class McpConfig:
    bind: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"


@dataclass
class DashboardConfig:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 8766


@dataclass
class ArtifactsConfig:
    dir: str = "artifacts"
    reports_dir: str = "reports"
    pdb_cache: str = "artifacts/symbols"
    # v0.18: absolute path to the shared knowledge-base DB. When empty,
    # resolves to `<dir>/findings.db` — but that path is relative to the
    # server's cwd, which is what caused the pre-v0.18 two-DB drift.
    # Set this in configs/*.yaml to an absolute path to pin the DB
    # regardless of where suspex-server is launched from.
    findings_db: str = ""


@dataclass
class IdaConfig:
    enabled: bool = True
    ida_path: str = ""  # local IDA install, e.g. D:\\Apps\\IDA
    command: list[str] = field(default_factory=lambda: ["uv", "run", "idalib-mcp", "--stdio"])
    prefer_gui: bool = False
    open_timeout_s: int = 180


@dataclass
class GhidraConfig:
    # Disabled by default: the bridge only spawns once a Ghidra install +
    # JDK + pyghidra are configured. Enabling without prerequisites makes
    # ghidra_manage report an actionable precheck error at first use.
    enabled: bool = False
    ghidra_dir: str = ""   # Ghidra install root (GHIDRA_INSTALL_DIR)
    java_home: str = ""    # JDK home (JAVA_HOME); empty = rely on PATH
    project_dir: str = ""  # shared Ghidra project dir; default <artifacts>/ghidra_project
    project_name: str = "suspex"
    backend_python: str = ""  # interpreter with pyghidra+mcp; empty = auto-detect
    heap_mb: int = 8192    # JVM -Xmx for the one shared backend
    open_timeout_s: int = 300  # JVM+import+analysis can be slower than idalib
    open_soft_deadline_s: float = 10.0
    # Shim command override (tests / exotic layouts). Empty = spawn
    # orchestrator/ghidra_stdio_shim.py with the current interpreter.
    command: list[str] = field(default_factory=list)


@dataclass
class PluginsConfig:
    dir: str = ""  # empty: auto-resolve to repo-root plugins (+ scripts_user overlay)


@dataclass
class SymbolsConfig:
    # PDB-backed kernel symbol resolution (dbghelp). Cache lives at
    # artifacts.pdb_cache in symsrv layout.
    allow_download: bool = True
    servers: list[str] = field(
        default_factory=lambda: ["https://msdl.microsoft.com/download/symbols"])


@dataclass
class LoggingConfig:
    # Root log level (DEBUG/INFO/WARNING/...). `file` is optional: empty
    # means log to stderr only; a path adds a FileHandler alongside it.
    level: str = "INFO"
    file: str = ""


@dataclass
class ClientsConfig:
    # Idle AgentClient reaper: how long a per-target client may sit unused
    # before the caller-side pool tears down its channel. Keeps long sessions
    # from pinning gRPC connections to targets no one is talking to anymore.
    idle_reap_s: float = 300.0


@dataclass
class LeasesConfig:
    # Default wait when a peer tries to attach to a pid that is already
    # attached under someone else's lease. Zero fails fast; larger values
    # let short-lived attaches drain naturally.
    attach_timeout_s: float = 5.0
    # Default wait for driver_load / driver_unload arbitration when multiple
    # agents contend for the driver. Longer than attach_timeout because these
    # operations touch the SCM and can legitimately take seconds.
    driver_timeout_s: float = 10.0


@dataclass
class WatchdogConfig:
    # v0.25: hands-off wedge protection. When `auto_arm` carries an `id`,
    # target_manage(driver_load|connect-new_boot) re-arms the driver
    # watchdog and attaches an orchestrator-side kicker automatically —
    # protection resumes after a driver load and after a reboot without a
    # manual watchdog_manage(auto_kick) call. Empty dict = disabled.
    # Shape: {id, deadline_ms, interval_ms, bugcheck_code, cookie, label}
    auto_arm: dict[str, Any] = field(default_factory=dict)


@dataclass
class SnapshotsConfig:
    # v0.25: periodic pre-crash state capture. "Snapshot on heartbeat
    # loss" is impossible — a wedged target can't answer reads — so the
    # pump captures every configured range on an interval while the
    # target is alive; artifacts/snapshots/<boot_epoch_ms>/ survives the
    # BSOD that follows. enabled=false with non-empty ranges leaves the
    # pump off but the config in place.
    enabled: bool = False
    interval_s: float = 30.0
    # Each range: {name, space (user|kernel|physical), address|from_va,
    # size, pid?}. `address` honors module+offset notation resolved once
    # per boot; `from_va` + space=physical translates VA->PA then reads
    # the physical page.
    ranges: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SuspexConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    # named secondary targets (phase 1): e.g. targets.user -> the umagent
    # usermode view. Falls back to `target` for the primary name.
    targets: dict[str, TargetConfig] = field(default_factory=dict)
    # multi-machine: machines.<alias> = {host, token, kernel_port,
    # user_port, views...} — each alias's views are addressable as
    # '<alias>.<kind>' (lab2.kernel). computer_name also resolves.
    machines: dict[str, MachineConfig] = field(default_factory=dict)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    mcp: McpConfig = field(default_factory=McpConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    artifacts: ArtifactsConfig = field(default_factory=ArtifactsConfig)
    ida: IdaConfig = field(default_factory=IdaConfig)
    ghidra: GhidraConfig = field(default_factory=GhidraConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    symbols: SymbolsConfig = field(default_factory=SymbolsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    clients: ClientsConfig = field(default_factory=ClientsConfig)
    leases: LeasesConfig = field(default_factory=LeasesConfig)
    watchdog: WatchdogConfig = field(default_factory=WatchdogConfig)
    snapshots: SnapshotsConfig = field(default_factory=SnapshotsConfig)

    @property
    def target_endpoint(self) -> str:
        return f"{self.target.host}:{self.target.port}"

    def target_for(self, name: str | None = None) -> TargetConfig:
        if name and name in self.targets:
            return self.targets[name]
        if name and "." in name:
            # '<machine>.<kind>' — resolve inside that machine's scope;
            # never fall back to another machine's endpoint.
            label, kind = name.rsplit(".", 1)
            if label in self.machines:
                return self.machines[label].view(kind)
            if label in self.targets:  # machine-wide shared entry
                return self.targets[label]
            raise KeyError(f"unknown target {name!r}")
        if name and name in self.machines:
            # bare machine alias -> its kernel view
            return self.machines[name].view(PRIMARY_TARGET)
        if name and name != PRIMARY_TARGET:
            raise KeyError(f"unknown target {name!r}")
        return self.target

    def machine_for_endpoint(self, host: str, port: int) -> str:
        """Config alias whose view endpoint matches host:port — lets a
        machine keep a stable label when its IP changes."""
        for alias, m in self.machines.items():
            for kind in (list(m.views) or ["kernel", "user"]):
                tc = m.view(kind)
                if tc.host == host and (not port or tc.port == int(port)):
                    return alias
        for name, tc in self.targets.items():
            if "." not in name:
                continue  # undotted entries are view-kind/default endpoints
            if tc.host == host and (not port or tc.port == int(port)):
                return self.machine_of_key(name)
        return ""

    @staticmethod
    def machine_of_key(view_key: str) -> str:
        return view_key.rsplit(".", 1)[0] if "." in view_key else view_key

    def _anchored(self, raw: str) -> Path:
        """Absolute paths pass through; relative ones anchor at the
        source-checkout repo root so every launch lands on the same
        store regardless of cwd."""
        p = Path(raw)
        if p.is_absolute():
            return p
        return _project_root() / p

    def artifacts_dir(self) -> Path:
        """Canonical artifact root — the ONE namespace shared by every
        producer and consumer (file_manage dumps/ingest, spill,
        store_binary workdirs, bin_manage/ida_manage lookups).

        Precedence matches the IDA shim: SUSPX_ARTIFACTS_DIR (absolute)
        > artifacts.dir anchored at the repo root."""
        import os
        envd = (os.environ.get("SUSPX_ARTIFACTS_DIR") or "").strip()
        if envd:
            return Path(envd)
        return self._anchored(self.artifacts.dir)

    def reports_dir(self) -> Path:
        return self._anchored(self.artifacts.reports_dir)

    def pdb_cache_dir(self) -> Path:
        """PDB cache root — anchored like artifacts_dir so dbghelp and
        the IDA shim agree on the same symsrv tree."""
        return self._anchored(self.artifacts.pdb_cache)

    def findings_db(self) -> Path:
        """v0.18: canonical path to the shared knowledge-base DB.

        Precedence:
          1. artifacts.findings_db (config field, may be absolute).
          2. artifacts.dir/findings.db (relative to cwd — the pre-v0.18
             default that caused two DBs to accumulate).
        Pin an absolute path in configs/*.yaml to guarantee every
        orchestrator boot lands on the same DB.
        """
        pinned = (self.artifacts.findings_db or "").strip()
        if pinned:
            return Path(pinned)
        return self.artifacts_dir() / "findings.db"

    def spill_dir(self) -> Path:
        """v0.14 auto-spill lives under artifacts_dir/spill/. Content-addressed
        by sha256; identical payloads dedupe naturally. Read back via
        file_manage(action='read_artifact', sha256=...).

        Precedence matches the IDA-shim's `_shim_spill_dir()` so the
        orchestrator and the shim always land on the same directory:
        SUSPX_MCP_SPILL_DIR (absolute) > SUSPX_ARTIFACTS_DIR/spill >
        artifacts.dir/spill.
        """
        import os
        envd = os.environ.get("SUSPX_MCP_SPILL_DIR")
        if envd:
            return Path(envd)
        art = os.environ.get("SUSPX_ARTIFACTS_DIR")
        if art:
            return Path(art) / "spill"
        return self.artifacts_dir() / "spill"

    # --- v0.14 MCP response-size envelopes -----------------------------------
    # Env-var overrides let deployments tune spill without touching yaml.

    def mcp_max_bytes(self) -> int:
        """Response byte budget; over this the biggest field in `data` spills.
        Default 32 KiB. Set SUSPX_MCP_MAX_BYTES to change; -1 disables spill.
        """
        import os
        try:
            return int(os.environ.get("SUSPX_MCP_MAX_BYTES", "32768"))
        except ValueError:
            return 32768

    def mcp_max_items(self) -> int:
        """Global cap on list-length across every list-returning action.
        Default 256. Set SUSPX_MCP_MAX_ITEMS to change."""
        import os
        try:
            return int(os.environ.get("SUSPX_MCP_MAX_ITEMS", "256"))
        except ValueError:
            return 256

    def mcp_preview_bytes(self) -> int:
        """Bytes/chars kept inline as `preview` when a payload spills.
        Default 512. Set SUSPX_MCP_PREVIEW_BYTES to change."""
        import os
        try:
            return int(os.environ.get("SUSPX_MCP_PREVIEW_BYTES", "512"))
        except ValueError:
            return 512


def _merge(dc: Any, data: dict[str, Any]) -> Any:
    """Shallow-merge a dict onto a dataclass instance, ignoring unknown keys."""
    if not isinstance(data, dict):
        return dc
    fields = {f.name: f for f in dataclasses.fields(dc)}
    for key, value in data.items():
        if key in fields:
            setattr(dc, key, value)
    return dc


def load_config(path: str | Path | None) -> SuspexConfig:
    cfg = SuspexConfig()
    if path is None:
        return cfg
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping: {path}")
    _merge(cfg.target, raw.get("target"))
    raw_targets = raw.get("targets")
    if isinstance(raw_targets, dict):
        for name, data in raw_targets.items():
            tc = TargetConfig()
            _merge(tc, data)
            cfg.targets[str(name)] = tc
    raw_machines = raw.get("machines")
    if isinstance(raw_machines, dict):
        for alias, data in raw_machines.items():
            if not isinstance(data, dict):
                continue
            mc = MachineConfig()
            _merge(mc, data)
            for kind, vdata in data.items():
                if isinstance(vdata, dict):
                    tc = TargetConfig()
                    _merge(tc, vdata)
                    mc.views[str(kind)] = tc
            cfg.machines[str(alias)] = mc
    _merge(cfg.security, raw.get("security"))
    _merge(cfg.mcp, raw.get("mcp"))
    _merge(cfg.dashboard, raw.get("dashboard"))
    _merge(cfg.artifacts, raw.get("artifacts"))
    _merge(cfg.ida, raw.get("ida"))
    _merge(cfg.ghidra, raw.get("ghidra"))
    _merge(cfg.plugins, raw.get("plugins"))
    _merge(cfg.symbols, raw.get("symbols"))
    _merge(cfg.logging, raw.get("logging"))
    _merge(cfg.clients, raw.get("clients"))
    _merge(cfg.leases, raw.get("leases"))
    _merge(cfg.watchdog, raw.get("watchdog"))
    _merge(cfg.snapshots, raw.get("snapshots"))
    return cfg
