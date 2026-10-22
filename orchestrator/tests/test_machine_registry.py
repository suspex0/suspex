"""v0.30 machine registry — persistence, metadata/trust, shadow rules,
minimal envelope stamp policy, actuator trust gate, one-time
machine_info banner.
"""

from __future__ import annotations

import json
import os

import pytest

from suspex.config import SuspexConfig
from suspex.registry import DEFAULT_ALIAS, MachineRegistry
from suspex.session import Session


def _cfg(tmp_path):
    cfg = SuspexConfig()
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    return cfg


def _registry(tmp_path, cfg=None) -> MachineRegistry:
    cfg = cfg or _cfg(tmp_path)
    # same path MachineRegistry.load() resolves (artifacts/targets.json)
    return MachineRegistry(cfg, tmp_path / "artifacts" / "targets.json")


class TestRegistryCrud:
    def test_register_persists_and_merges_into_cfg(self, tmp_path):
        cfg = _cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        info = reg.register("lab3", host="10.0.2.20", kernel_port=50074,
                            user_port=50075, token="s3cr3t-value",
                            trust="lab", purpose="delta rig",
                            note="testsigning on", operator="hco3",
                            tags=["win11", "testsigning"])
        assert info["machine"] == "lab3"
        assert info["trust"] == "lab"
        assert info["purpose"] == "delta rig"
        assert info["endpoints"]["kernel"] == "10.0.2.20:50074"
        assert info["token_set"] is True
        # never leak the credential
        assert "s3cr3t-value" not in json.dumps(info)
        # cfg.machines got the entry so view resolution works
        tc = cfg.target_for("lab3.kernel")
        assert (tc.host, tc.port) == ("10.0.2.20", 50074)
        # file survives a reload
        reg2 = MachineRegistry.load(cfg)
        assert reg2.entry("lab3")["purpose"] == "delta rig"

    def test_set_partial_update(self, tmp_path):
        reg = _registry(tmp_path)
        reg.register("lab3", host="10.0.2.20", kernel_port=50074)
        info = reg.set("lab3", trust="restricted", note="moved racks",
                       tags=["win10"])
        assert info["trust"] == "restricted"
        assert info["note"] == "moved racks"
        assert info["tags"] == ["win10"]
        assert info["purpose"] == ""          # untouched
        assert info["endpoints"]["kernel"] == "10.0.2.20:50074"  # untouched

    def test_unregister_removes(self, tmp_path):
        cfg = _cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        reg.register("lab3", host="10.0.2.20", kernel_port=50074)
        assert reg.unregister("lab3") is True
        assert reg.entry("lab3") is None
        assert "lab3" not in cfg.machines
        assert reg.unregister("lab3") is False

    def test_env_var_token_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SUSPEX_TEST_TOKEN", "sekret-from-env")
        cfg = _cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        reg.register("lab3", host="10.0.2.20", kernel_port=50074,
                     token="${SUSPEX_TEST_TOKEN}")
        assert cfg.machines["lab3"].token == "sekret-from-env"

    def test_bad_aliases_rejected(self, tmp_path):
        reg = _registry(tmp_path)
        with pytest.raises(ValueError):
            reg.register("", host="x")
        with pytest.raises(ValueError):
            reg.register("has space", host="x")

    def test_default_alias_metadata_only(self, tmp_path):
        reg = _registry(tmp_path)
        info = reg.register(DEFAULT_ALIAS, trust="lab", purpose="primary box")
        assert info["trust"] == "lab"
        with pytest.raises(ValueError):
            reg.register(DEFAULT_ALIAS, host="10.0.0.1", kernel_port=1)


class TestYamlShadowRules:
    def _yaml_cfg(self, tmp_path):
        cfg = _cfg(tmp_path)
        from suspex.config import MachineConfig
        cfg.machines["lab2"] = MachineConfig(host="10.0.2.15", token="ytok",
                                             kernel_port=50099)
        return cfg

    def test_registry_refuses_endpoint_shadow(self, tmp_path):
        cfg = self._yaml_cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        with pytest.raises(ValueError):
            reg.register("lab2", host="10.9.9.9", kernel_port=1234)
        # metadata-only overlay is fine
        info = reg.register("lab2", trust="lab", purpose="yaml box")
        assert info["purpose"] == "yaml box"
        assert cfg.machines["lab2"].host == "10.0.2.15"

    def test_force_shadow_and_restore(self, tmp_path):
        cfg = self._yaml_cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        reg.register("lab2", host="10.9.9.9", kernel_port=1234, force=True)
        assert cfg.machines["lab2"].host == "10.9.9.9"
        with pytest.raises(ValueError):
            reg.unregister("lab2")          # shadow needs force
        assert reg.unregister("lab2", force=True) is True
        # pristine reviewed-config restored
        assert cfg.machines["lab2"].host == "10.0.2.15"
        assert cfg.machines["lab2"].token == "ytok"

    def test_set_endpoint_on_yaml_alias_needs_force(self, tmp_path):
        cfg = self._yaml_cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        reg.register("lab2", purpose="yaml box")
        with pytest.raises(ValueError):
            reg.set("lab2", host="10.9.9.9")
        info = reg.set("lab2", host="10.9.9.9", force=True)
        assert info["endpoints"].get("kernel") == "10.9.9.9:50099"


class TestTrustLookup:
    def test_precedence(self, tmp_path):
        from suspex.config import MachineConfig
        cfg = _cfg(tmp_path)
        cfg.machines["yamlbox"] = MachineConfig(host="h", trust="restricted")
        reg = _registry(tmp_path, cfg)
        # yaml metadata without registry entry
        assert reg.trust_for("yamlbox") == "restricted"
        # registry entry wins over yaml
        reg.register("yamlbox", trust="lab")
        assert reg.trust_for("yamlbox") == "lab"
        # default overlay for the implicit machine's learned label
        reg.register(DEFAULT_ALIAS, trust="lab")
        assert reg.trust_for("DESKTOP-ANY") == "lab"
        # unknown label with no default -> fail-safe
        reg.unregister(DEFAULT_ALIAS)
        assert reg.trust_for("DESKTOP-ANY") == "untrusted"
        # garbage trust strings normalize to untrusted
        reg.register("weird", trust="kinda")
        assert reg.trust_for("weird") == "untrusted"


class TestStampPolicy:
    def _session(self, tmp_path, views):
        cfg = _cfg(tmp_path)
        s = Session(cfg)
        for v in views:
            s.clients[v] = object()
        return s

    def test_single_view_no_stamp(self, tmp_path):
        s = self._session(tmp_path, ["lab2.kernel"])
        assert s.stamp_needed("lab2.kernel") is False

    def test_multi_view_stamps(self, tmp_path):
        s = self._session(tmp_path, ["lab2.kernel", "lab3.kernel"])
        assert s.stamp_needed("lab2.kernel") is True

    def test_focus_mismatch_stamps(self, tmp_path):
        from suspex.caller import current_client_id
        s = self._session(tmp_path, ["lab2.kernel", "lab2.user"])
        s._focus[current_client_id()] = {"machine": "lab2", "kind": "kernel"}
        assert s.stamp_needed("lab2.kernel") is True   # >1 view
        s2 = self._session(tmp_path, ["lab2.kernel"])
        s2._focus[current_client_id()] = {"machine": "other", "kind": "kernel"}
        assert s2.stamp_needed("lab2.kernel") is True  # != focus machine
        s3 = self._session(tmp_path, ["lab2.kernel"])
        s3._focus[current_client_id()] = {"machine": "lab2", "kind": "kernel"}
        assert s3.stamp_needed("lab2.kernel") is False

    def test_stamp_target_emits_bare_view_key(self, tmp_path):
        from types import SimpleNamespace

        from suspex.mcp.tools.common import _stamp_target
        cfg = _cfg(tmp_path)
        s = Session(cfg)
        s.clients["lab2.kernel"] = object()
        s.clients["lab3.kernel"] = object()
        ctx = SimpleNamespace(session=s)
        env = _stamp_target({}, ctx, {"name": "lab2.kernel"})
        assert env["target"] == "lab2.kernel"    # bare string, not a dict


class TestActuatorTrustGate:
    def _ctx(self, tmp_path, trust: str, min_trust: str):
        from types import SimpleNamespace

        from suspex.mcp.tools.common import _check_actuator_trust
        cfg = _cfg(tmp_path)
        cfg.security.min_trust_actuator = min_trust
        reg = _registry(tmp_path, cfg)
        reg.register("lab3", host="10.0.2.20", kernel_port=50074,
                     trust=trust)
        s = Session(cfg)
        s.clients["lab3.kernel"] = object()
        ctx = SimpleNamespace(cfg=cfg, session=s, registry=reg)
        return _check_actuator_trust, ctx

    def test_refused_below_threshold(self, tmp_path):
        from suspex.allowlist import TargetNotAllowed
        check, ctx = self._ctx(tmp_path, "untrusted", "lab")
        with pytest.raises(TargetNotAllowed):
            check(ctx, "device_manage", "ioctl",
                  {"name": "lab3.kernel", "code": 1})

    def test_allowed_at_threshold(self, tmp_path):
        check, ctx = self._ctx(tmp_path, "lab", "lab")
        check(ctx, "device_manage", "ioctl",
              {"name": "lab3.kernel", "code": 1})          # no raise

    def test_force_overrides(self, tmp_path):
        check, ctx = self._ctx(tmp_path, "untrusted", "lab")
        check(ctx, "device_manage", "ioctl",
              {"name": "lab3.kernel", "code": 1, "force": True})  # no raise

    def test_gating_off_by_default(self, tmp_path):
        check, ctx = self._ctx(tmp_path, "untrusted", "untrusted")
        check(ctx, "exec_manage", "call", {"name": "lab3.kernel"})  # no raise

    def test_reads_never_gated(self, tmp_path):
        check, ctx = self._ctx(tmp_path, "untrusted", "lab")
        check(ctx, "mem_rw", "read", {"name": "lab3.kernel"})       # not an actuator

    def test_unresolvable_machine_fails_closed_via_default(self, tmp_path):
        from suspex.allowlist import TargetNotAllowed
        check, ctx = self._ctx(tmp_path, "untrusted", "lab")
        with pytest.raises(TargetNotAllowed):
            check(ctx, "exec_manage", "kill_process",
                  {"name": "nonexistent.kernel", "pid": 1})


class TestMachineInfoBanner:
    def test_banner_once_per_client(self, tmp_path):
        from types import SimpleNamespace

        from suspex.mcp.tools.target import _attach_machine_info
        cfg = _cfg(tmp_path)
        reg = _registry(tmp_path, cfg)
        reg.register("lab3", host="10.0.2.20", kernel_port=50074,
                     trust="lab", purpose="delta rig")
        s = Session(cfg)
        s.clients["lab3.kernel"] = object()
        s.clients["lab3.user"] = object()
        ctx = SimpleNamespace(cfg=cfg, session=s, registry=reg,
                              _machine_info_seen={})
        first = _attach_machine_info(ctx, "cid1", "lab3.kernel")
        assert first is not None and first["trust"] == "lab"
        assert first["purpose"] == "delta rig"
        # same client, same machine (other view): silent
        assert _attach_machine_info(ctx, "cid1", "lab3.user") is None
        # a different client gets introduced
        second = _attach_machine_info(ctx, "cid2", "lab3.kernel")
        assert second is not None and second["machine"] == "lab3"
