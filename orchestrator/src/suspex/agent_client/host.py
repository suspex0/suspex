"""Host / Agent-service methods (status, driver, host_info, watchdog)."""

from __future__ import annotations

from typing import Any

from ..generated import suspex_pb2 as pb
from .wire import proto_to_dict, status_dict


class HostMixin:
    # ---------------------------------------------------------------- Agent ----

    async def status(self) -> dict[str, Any]:
        msg = await self._call(self.agent.Status, pb.StatusRequest())
        d = proto_to_dict(msg)
        d["ok"] = msg.status.ok
        return d

    async def driver_load(self, method: str = "service", image_path: str = "") -> dict[str, Any]:
        req = pb.DriverLoadRequest(
            method=pb.DriverLoadRequest.MANUAL_MAP if method == "manual_map" else pb.DriverLoadRequest.SERVICE,
            image_path=image_path,
        )
        st = await self._call(self.agent.DriverLoad, req)
        return status_dict(st)

    async def driver_unload(self, delete_service: bool = True) -> dict[str, Any]:
        st = await self._call(self.agent.DriverUnload, pb.DriverUnloadRequest(delete_service=delete_service))
        return status_dict(st)

    async def self_update(self, service_name: str, exe_path: str, staged_path: str,
                          sha256: str = "", listen_port: str = "") -> dict[str, Any]:
        """Detached swap-and-restart of a service binary on the target. The
        agent spawns an updater script that stops the service, kills any
        process still holding the image, quarantines the old exe under prev/,
        promotes `staged_path`, restarts, port-checks, and rolls back on
        failure. The call returns before the service actually goes away."""
        if not hasattr(pb, "SelfUpdateRequest") or not hasattr(self.agent, "SelfUpdate"):
            return {"ok": False,
                    "error": "self_update: agent predates the SelfUpdate RPC — "
                             "use exec-based swap or rebuild the agent"}
        st = await self._call(self.agent.SelfUpdate, pb.SelfUpdateRequest(
            service_name=service_name, exe_path=exe_path, staged_path=staged_path,
            sha256=sha256, listen_port=listen_port))
        return status_dict(st)

    async def host_info(self, include_security_products: bool = False,
                        include_hardware: bool = True) -> dict[str, Any]:
        """v8: broad target-machine fingerprint. Identity, full OS release
        (product name / UBR / display version), security posture (secure
        boot, VBS, driver blocklist, LSA-PPL, CPU features, kernel
        debugger), optional hardware/hypervisor + WSC security products.

        Every security-posture bit carries a `<name>_source` sibling
        ("driver" > "registry" > "api" > "unknown") so the caller can tell
        confidence apart. `probe_errors` lists probes that couldn't answer.

        Older agents that don't know Agent.HostInfo get a clear
        `{ok:false, error:"agent < v8 ..."}` — a v7 orchestrator survives
        against a v6 agent, and vice versa.
        """
        if not hasattr(pb, "HostInfoRequest") or not hasattr(self.agent, "HostInfo"):
            return {"ok": False,
                    "error": "host_info: agent < v8 (Agent.HostInfo missing)"}
        req = pb.HostInfoRequest(
            include_security_products=include_security_products,
            include_hardware=include_hardware,
        )
        msg = await self._call(self.agent.HostInfo, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        # We don't use proto_to_dict here because the response is deeply
        # non-uniform (grouped identity/OS/posture/hardware/uptime) and
        # the orchestrator's confidence envelope wants raw pairs.
        def _flag(v, src):
            return {"value": bool(v), "source": src or "unknown"}
        return {
            "ok": True,
            "identity": {
                "computer_name": msg.computer_name,
                "dns_hostname": msg.dns_hostname,
                "domain": msg.domain,
                "logged_on_user": msg.logged_on_user,
                "agent_run_as": msg.agent_run_as,
                "is_elevated": msg.is_elevated,
            },
            "os": {
                "product_name": msg.product_name,
                "edition_id": msg.edition_id,
                "display_version": msg.display_version,
                "release_id": msg.release_id,
                "build_major": msg.build_major,
                "build_ubr": msg.build_ubr,
                "full_build_string": msg.full_build_string,
                "install_date": msg.install_date,
                "boot_time": msg.boot_time,
                "timezone": msg.timezone,
                "arch": msg.arch,
            },
            "security": {
                "testsigning": _flag(msg.testsigning, msg.testsigning_source),
                "hvci": _flag(msg.hvci, msg.hvci_source),
                "secureboot": _flag(msg.secureboot, msg.secureboot_source),
                "kernel_debugger": _flag(msg.kernel_debugger, msg.kernel_debugger_source),
                "vbs_enabled": _flag(msg.vbs_enabled, msg.vbs_source),
                "credential_guard": _flag(msg.credential_guard, msg.credential_guard_source),
                "driver_blocklist_on": _flag(msg.driver_blocklist_on, msg.driver_blocklist_source),
                "lsa_protected": _flag(msg.lsa_protected, msg.lsa_protected_source),
                "smep": msg.smep,
                "smap": msg.smap,
                "cet_shstk": msg.cet_shstk,
                "patchguard_state": msg.patchguard_state,
                # v0.13 dev-feedback: KVA shadow (Meltdown mitigation). Only
                # populated when the agent was rebuilt with the probe; older
                # agents leave the proto fields at their defaults (bool
                # false, empty source) so we surface as source='unknown'.
                "kva_shadow": _flag(getattr(msg, "kva_shadow", False),
                                     getattr(msg, "kva_shadow_source", "") or "unknown"),
            },
            "hardware": {
                "cpu_brand": msg.cpu_brand,
                "cpu_cores": msg.cpu_cores,
                "cpu_logical": msg.cpu_logical,
                "phys_mem_bytes": msg.phys_mem_bytes,
                "hypervisor_vendor": msg.hypervisor_vendor,
                "is_vm": msg.is_vm,
            },
            "uptime": {
                "pc_uptime_ms": msg.pc_uptime_ms,
                "agent_uptime_ms": msg.agent_uptime_ms,
                "service_uptime_ms": msg.service_uptime_ms,
            },
            "security_products": [
                {"name": p.name, "state": p.state,
                 "version": p.version, "kind": p.kind}
                for p in msg.security_products
            ],
            "probe_errors": list(msg.probe_errors),
            # v0.31 Phase 2.1: adapter list for registry self-heal /
            # rediscover. Empty on agents that predate the field.
            "ipv4": [
                {"adapter": a.adapter, "address": a.address,
                 "prefix_len": a.prefix_len, "origin": a.origin,
                 "gateway": a.gateway, "mac": a.mac, "up": a.up}
                for a in (getattr(msg, "ipv4", None) or [])
            ],
        }

    async def recent_ops_agent(self, limit: int = 32,
                                include_prior: bool = True) -> dict[str, Any]:
        """Read the agent-side persistent breadcrumb ring (v5). `prior`
        entries are from the previous agent lifetime — anything marked
        `wedged` there is a call that was in flight when the agent died.
        """
        if not hasattr(self.agent, "RecentOps"):
            return {"ok": False,
                    "error": "recent_ops_agent: agent < v5 (Agent.RecentOps missing)"}
        req = pb.RecentOpsRequest(limit=limit, include_prior=include_prior)
        msg = await self._call(self.agent.RecentOps, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        def _dump(entries):
            return [{
                "t_start_us": e.t_start_us, "t_end_us": e.t_end_us,
                "latency_us": e.latency_us,
                "ioctl_code": e.ioctl_code, "arg_summary": e.arg_summary,
                "status_code": e.status_code, "status_kind": e.status_kind,
            } for e in entries]
        return {
            "ok": True,
            "agent_start_epoch_ms": msg.agent_start_epoch_ms,
            "now_epoch_ms": msg.now_epoch_ms,
            "current": _dump(msg.current),
            "prior": _dump(msg.prior),
        }

    # ------------------------------------------------------------- Watchdog ----
    # v8: driver-backed wedge-detector. Every call is unary; the actual
    # armed-deadline state lives in the driver. If the agent predates v8 we
    # return a named error so the MCP tool can surface it verbatim.

    def _wdg_missing(self, action: str) -> dict[str, Any]:
        return {"ok": False,
                "error": f"watchdog {action}: agent < v8 (Watchdog service missing)",
                "hint": "rebuild + redeploy agent+driver for the ABI v8 watchdog"}

    async def watchdog_arm(self, wid: int, deadline_ms: int, *,
                           bugcheck_code: int = 0, flags: int = 0,
                           cookie: int = 0, label: str = "") -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("arm")
        req = pb.WdgArmRequest(id=int(wid), deadline_ms=int(deadline_ms),
                               bugcheck_code=int(bugcheck_code), flags=int(flags),
                               cookie=int(cookie), label=str(label)[:31])
        st = await self._call(self.watchdog.Arm, req)
        return {"ok": st.status.ok, "error": st.status.error,
                "id": int(wid), "deadline_ms": int(deadline_ms)}

    async def watchdog_kick(self, wid: int, *, deadline_ms: int = 0,
                            cookie: int = 0) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("kick")
        req = pb.WdgKickRequest(id=int(wid), deadline_ms=int(deadline_ms),
                                cookie=int(cookie))
        msg = await self._call(self.watchdog.Kick, req)
        return {"ok": msg.status.ok, "error": msg.status.error,
                "id": int(wid), "kick_count": int(msg.kick_count),
                "last_kick_us": int(msg.last_kick_us),
                "deadline_us": int(msg.deadline_us)}

    async def watchdog_disarm(self, wid: int) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("disarm")
        req = pb.WdgDisarmRequest(id=int(wid))
        st = await self._call(self.watchdog.Disarm, req)
        return {"ok": st.ok, "error": st.error, "id": int(wid)}

    async def watchdog_list(self) -> dict[str, Any]:
        if self.watchdog is None:
            return self._wdg_missing("list")
        msg = await self._call(self.watchdog.List, pb.WdgListRequest())
        entries = []
        for e in msg.entries:
            entries.append({
                "id": int(e.id),
                "bugcheck_code": int(e.bugcheck_code),
                "deadline_us": int(e.deadline_us),
                "last_kick_us": int(e.last_kick_us),
                "kick_count": int(e.kick_count),
                "cookie": int(e.cookie),
                "armed_us": int(e.armed_us),
                "label": str(e.label),
                "remaining_ms": int(e.remaining_ms),
            })
        return {"ok": msg.status.ok, "error": msg.status.error,
                "now_us": int(msg.now_us), "count": len(entries),
                "entries": entries}

    # ------------------------------------------------------ Screen (v15) ----

    async def capture_screen(self, mode: str = "desktop", display_id: str = "",
                             hwnd: int = 0, pid: int = 0,
                             window_title: str = "", process_name: str = "",
                             query: str = "", max_dimension: int = 1920,
                             include_hidden: bool = False,
                             include_details: bool = True) -> dict[str, Any]:
        """Desktop/window screenshot (PNG bytes inline) + window telemetry JSON."""
        req = pb.ScreenCaptureRequest(
            mode=mode,
            display_id=display_id,
            hwnd=hwnd,
            pid=pid,
            window_title=window_title,
            process_name=process_name,
            query=query,
            max_dimension=max_dimension,
            include_hidden=include_hidden,
            include_details=include_details,
        )
        msg = await self._call(self.agent.CaptureScreen, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "target_type": msg.target_type,
            "target_name": msg.target_name,
            "image_data": msg.image_data,
            "width": int(msg.width),
            "height": int(msg.height),
            "timestamp_unix_ms": int(msg.timestamp_unix_ms),
            "windows_json": msg.windows_json,
        }

    async def list_windows(self, pid: int = 0, process_name: str = "",
                           query: str = "", include_hidden: bool = False,
                           include_details: bool = True) -> dict[str, Any]:
        """Window list from the session-1 worker (windows_json is authoritative)."""
        req = pb.WindowListRequest(
            pid=pid,
            process_name=process_name,
            query=query,
            include_hidden=include_hidden,
            include_details=include_details,
        )
        msg = await self._call(self.agent.ListWindows, req)
        return {
            "ok": msg.status.ok,
            "error": msg.status.error if not msg.status.ok else None,
            "total_windows": int(msg.total_windows),
            "windows_json": msg.windows_json,
        }
