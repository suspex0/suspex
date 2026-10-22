"""Multi-machine sessions — '<machine>.<kind>' view keys, per-chat focus,
machine-identity aliases, and the ``machines:`` config block.

Covers:
  * config: ``machines:`` yaml in both shapes — flat
    ``{host, token, kernel_port, user_port}`` and nested
    ``kernel: {...} / user: {...}`` view overrides — expanding to
    ``MachineConfig.view`` / ``target_for`` / ``machine_for_endpoint``.
  * ``Session.connect`` naming: ``machine=`` arg, dotted ``name=``, and
    learned labels (computer_name > config alias > host) plus the
    duplicate-connect attach path.
  * per-owner auto-focus + ``set_focus`` / ``clear_focus`` / ``focus_of``.
  * ``resolve_view_name`` for every selector shape, including
    ``AmbiguousTargetError`` on an unfocused empty selector.
  * primary repoint after disconnect + ``machines()`` /
    ``machine_label()`` / ``target_stamp()``.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from suspex.config import MachineConfig, SuspexConfig, load_config
from suspex.session import AmbiguousTargetError, Session


# --------------------------------------------------------------------------- #
# Fake AgentClient stand-in — connect/status/host_info/close surface.
# --------------------------------------------------------------------------- #


class _FakeAgentClient:
    """Duck-typed AgentClient for Session.connect/disconnect exercise.

    ``computer_names`` maps (host, port) -> the computer_name host_info
    should report, so tests can steer the learned machine label.
    ``instances`` records every constructed channel so dedup/attach paths
    can assert on channels that were built then thrown away.
    """

    instances: list["_FakeAgentClient"] = []
    computer_names: dict[tuple[str, int], str] = {}

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._closed = False
        self.last_op_ts = time.time()
        self.last_seen_ts = time.time()
        self.connected_ts = time.time()
        _FakeAgentClient.instances.append(self)

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self._closed = True

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": self.endpoint,
                "boot_epoch_ms": 1000 + self.port,
                "agent_instance_id": f"agent-{self.port}"}

    async def host_info(self, *, include_hardware: bool = False,
                        include_security_products: bool = False
                        ) -> dict[str, Any]:
        cn = _FakeAgentClient.computer_names.get(
            (self.host, self.port), "")
        return {"ok": True, "identity": {"computer_name": cn}}


@pytest.fixture()
def fake_agent_class(monkeypatch):
    """Patch in the fake channel + skip the real TCP pre-flight probe.

    Session creation also spawns an AuditWriter; SUSPX_AUDIT_DISABLE keeps
    the run from materializing a ~/.suspex0/audit tree.
    """
    _FakeAgentClient.instances.clear()
    _FakeAgentClient.computer_names.clear()
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    monkeypatch.setenv("SUSPX_AUDIT_DISABLE", "1")
    return _FakeAgentClient


def _mk_cfg() -> SuspexConfig:
    """Config with three loopback 'machines' so config-driven endpoint
    resolution works while the allowlist stays at its 127.0.0.0/8 default."""
    cfg = SuspexConfig()
    cfg.machines["lab2"] = MachineConfig(
        host="127.0.0.1", token="t2", kernel_port=5201, user_port=5202)
    cfg.machines["lab3"] = MachineConfig(
        host="127.0.0.1", token="t3", kernel_port=5301, user_port=5302)
    cfg.machines["lab5"] = MachineConfig(
        host="127.0.0.1", token="t5", kernel_port=5501, user_port=5502)
    return cfg


# --------------------------------------------------------------------------- #
# config: machines: block
# --------------------------------------------------------------------------- #


def test_load_config_machines_flat_ports(tmp_path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(
        "machines:\n"
        "  lab2:\n"
        "    host: 10.0.2.15\n"
        "    token: m-tok\n"
        "    kernel_port: 50099\n"
        "    user_port: 50075\n"
    )
    cfg = load_config(p)
    mc = cfg.machines["lab2"]
    k, u = mc.view("kernel"), mc.view("user")
    assert (k.host, k.port, k.token) == ("10.0.2.15", 50099, "m-tok")
    assert (u.host, u.port, u.token) == ("10.0.2.15", 50075, "m-tok")
    assert cfg.target_for("lab2.kernel").port == 50099
    assert cfg.target_for("lab2.user").port == 50075
    # Bare machine alias resolves to its kernel view.
    assert cfg.target_for("lab2").port == 50099
    with pytest.raises(KeyError):
        cfg.target_for("lab3.kernel")
    # Endpoint -> alias mapping covers both views.
    assert cfg.machine_for_endpoint("10.0.2.15", 50099) == "lab2"
    assert cfg.machine_for_endpoint("10.0.2.15", 50075) == "lab2"
    assert cfg.machine_for_endpoint("10.0.2.15", 4321) == ""


def test_load_config_machines_nested_views(tmp_path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(
        "machines:\n"
        "  lab4:\n"
        "    host: 10.0.2.20\n"
        "    token: shared-tok\n"
        "    kernel: {port: 51099, token: k-tok}\n"
        "    user: {host: 10.0.2.21, port: 51075}\n"
    )
    cfg = load_config(p)
    mc = cfg.machines["lab4"]
    # kernel override carries its own port+token; machine host fills in.
    k = mc.view("kernel")
    assert (k.host, k.port, k.token) == ("10.0.2.20", 51099, "k-tok")
    # user override carries its own host; machine token fills in.
    u = mc.view("user")
    assert (u.host, u.port, u.token) == ("10.0.2.21", 51075, "shared-tok")
    assert cfg.target_for("lab4.kernel").port == 51099
    assert cfg.target_for("lab4.user").host == "10.0.2.21"
    assert cfg.machine_for_endpoint("10.0.2.21", 51075) == "lab4"
    assert cfg.machine_for_endpoint("10.0.2.20", 51099) == "lab4"


# --------------------------------------------------------------------------- #
# connect naming
# --------------------------------------------------------------------------- #


async def test_connect_machine_arg_keys_view(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    status = await s.connect(host="127.0.0.1", port=6001, token="x",
                             machine="lab2", owner="chatA")
    assert "lab2.kernel" in s.clients
    assert status["view"] == "lab2.kernel"
    assert status["machine"] == "lab2"
    assert status["shared"] is False
    assert s.owners["lab2.kernel"] == "chatA"
    assert s.refs["lab2.kernel"] == {"chatA": 1}


async def test_connect_dotted_name_uses_config_endpoint(
        fake_agent_class) -> None:
    s = Session(_mk_cfg())
    status = await s.connect(name="lab2.user", owner="chatA")
    assert "lab2.user" in s.clients
    assert status["view"] == "lab2.user"
    # No host/port passed — endpoint came from the machines: block.
    assert (s.clients["lab2.user"].host,
            s.clients["lab2.user"].port) == ("127.0.0.1", 5202)


async def test_connect_bare_kind_learns_computer_name(
        fake_agent_class) -> None:
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-ABC"
    # No machines: entry matches the endpoint, so the label falls through
    # to the reported computer_name — case preserved in the key.
    s = Session(SuspexConfig())
    status = await s.connect(host="127.0.0.1", port=6001, name="kernel")
    assert "DESKTOP-ABC.kernel" in s.clients
    assert status["view"] == "DESKTOP-ABC.kernel"
    assert status["computer_name"] == "DESKTOP-ABC"
    assert s.primary == "DESKTOP-ABC.kernel"


async def test_connect_learned_key_reconnect_attaches(
        fake_agent_class) -> None:
    """A second bare-kind connect on the same endpoint lands on the
    already-learned key — the fresh channel is closed, not kept."""
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-ABC"
    s = Session(SuspexConfig())
    await s.connect(host="127.0.0.1", port=6001, name="kernel", owner="chatA")
    before = len(fake_agent_class.instances)
    status = await s.connect(host="127.0.0.1", port=6001, name="kernel",
                             owner="chatB")
    # The label is only learned after the channel is up, so a second
    # client was built — then deduped onto the live view and closed.
    assert len(fake_agent_class.instances) == before + 1
    assert fake_agent_class.instances[-1]._closed is True
    assert list(s.clients) == ["DESKTOP-ABC.kernel"]
    assert status["view"] == "DESKTOP-ABC.kernel"
    assert status["shared"] is True
    assert status["primary_owner"] == "chatA"
    assert s.refs["DESKTOP-ABC.kernel"] == {"chatA": 1, "chatB": 1}


async def test_connect_same_view_attaches_coowner(fake_agent_class) -> None:
    """Planned-key hit ('lab2.kernel' known pre-connect) attaches without
    building a channel at all."""
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x",
                    machine="lab2", owner="chatA")
    n = len(fake_agent_class.instances)
    status = await s.connect(host="127.0.0.1", port=6001, token="x",
                             machine="lab2", owner="chatB")
    assert len(fake_agent_class.instances) == n
    assert status["shared"] is True
    assert status["primary_owner"] == "chatA"
    assert s.refs["lab2.kernel"] == {"chatA": 1, "chatB": 1}


async def test_connect_sibling_view_inherits_machine_label(
        fake_agent_class) -> None:
    """umagent doesn't report computer_name — a view on a host that
    already has a connected view inherits that machine label instead of
    keying on the bare host."""
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-ABC"
    # umagent's host_info returns no computer_name.
    s = Session(SuspexConfig())
    await s.connect(host="127.0.0.1", port=6001, name="kernel")
    status = await s.connect(host="127.0.0.1", port=6002, name="user")
    assert status["view"] == "DESKTOP-ABC.user"
    assert "DESKTOP-ABC.user" in s.clients
    assert s.machines() == {"DESKTOP-ABC": ["DESKTOP-ABC.kernel",
                                          "DESKTOP-ABC.user"]}
    # The label-less view inherits computer_name for stamping.
    assert (s.machine_label("DESKTOP-ABC.user")["computer_name"]
            == "DESKTOP-ABC")


# --------------------------------------------------------------------------- #
# auto-focus
# --------------------------------------------------------------------------- #


async def test_connect_autofocuses_owner(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x",
                    machine="lab2", owner="chatA")
    assert s.focus_of("chatA") == {"machine": "lab2", "kind": "kernel"}
    # A different chat connecting a different machine gets its own focus
    # and does not move chatA's.
    await s.connect(host="127.0.0.1", port=6003, token="x",
                    machine="lab3", owner="chatB")
    assert s.focus_of("chatB") == {"machine": "lab3", "kind": "kernel"}
    assert s.focus_of("chatA") == {"machine": "lab2", "kind": "kernel"}
    assert s.focus_of("anonymous") is None


# --------------------------------------------------------------------------- #
# resolve_view_name — selector shapes
# --------------------------------------------------------------------------- #


async def test_resolve_single_machine_shapes(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    await s.connect(host="127.0.0.1", port=6002, token="x", name="lab2.user")
    # Two views on ONE machine — an empty selector is still unambiguous.
    assert s.resolve_view_name("") == "lab2.kernel"
    assert s.resolve_view_name("kernel") == "lab2.kernel"
    assert s.resolve_view_name("user") == "lab2.user"
    assert s.resolve_view_name("lab2") == "lab2.kernel"
    assert s.resolve_view_name("lab2.user") == "lab2.user"
    # Machine matching is case-insensitive; the connected key spelling
    # comes back.
    assert s.resolve_view_name("LAB2.kernel") == "lab2.kernel"
    # Literal connected key resolves to itself.
    assert s.resolve_view_name("lab2.kernel") == "lab2.kernel"


async def test_resolve_computer_name_alias(fake_agent_class) -> None:
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-ABC"
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    # computer_name is cached as an alias for the 'lab2' machine label.
    assert s.resolve_view_name("DESKTOP-ABC.kernel") == "lab2.kernel"
    assert s.resolve_view_name("desktop-abc") == "lab2.kernel"
    with pytest.raises(RuntimeError, match="unknown machine"):
        s.resolve_view_name("nope.kernel")


async def test_resolve_known_machine_missing_kind(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    with pytest.raises(RuntimeError, match="not connected"):
        s.resolve_view_name("lab2.user")
    with pytest.raises(RuntimeError, match="not connected"):
        s.require_client("lab2.user")


async def test_resolve_passthrough_verbatim(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    # Not a machine alias, not a bare kind — returned verbatim so legacy
    # raw-name callers keep working; require_client reports it missing.
    assert s.resolve_view_name("custom-name") == "custom-name"
    with pytest.raises(RuntimeError, match="not connected"):
        s.require_client("custom-name")


# --------------------------------------------------------------------------- #
# ambiguity + focus
# --------------------------------------------------------------------------- #


async def test_resolve_empty_ambiguous_without_focus(
        fake_agent_class) -> None:
    s = Session(_mk_cfg())
    # owner=None connects leave no focus behind.
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    await s.connect(host="127.0.0.1", port=6003, token="x", machine="lab5")
    with pytest.raises(AmbiguousTargetError) as exc:
        s.resolve_view_name("")
    assert exc.value.kind == "ambiguous_target"
    assert exc.value.machines == ["lab2", "lab5"]
    assert "use" in (exc.value.hint or "")


async def test_set_focus_disambiguates_per_chat(fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    await s.connect(host="127.0.0.1", port=6003, token="x", machine="lab5")
    await s.connect(host="127.0.0.1", port=6004, token="x", name="lab5.user")
    out = s.set_focus("chatC", "lab2")
    assert out["machine"] == "lab2" and out["kind"] == "kernel"
    assert out["view"] == "lab2.kernel"
    assert s.resolve_view_name("", "chatC") == "lab2.kernel"
    # Focus can carry an explicit view kind.
    s.set_focus("chatC", "lab5.user")
    assert s.resolve_view_name("", "chatC") == "lab5.user"
    # Focus is per-chat — another caller's focus stays independent.
    s.set_focus("chatD", "lab5")
    assert s.resolve_view_name("", "chatD") == "lab5.kernel"
    assert s.resolve_view_name("", "chatC") == "lab5.user"
    # Clearing focus drops straight back to ambiguous.
    assert s.clear_focus("chatC") is True
    with pytest.raises(AmbiguousTargetError):
        s.resolve_view_name("", "chatC")
    assert s.focus_of("chatD") == {"machine": "lab5", "kind": "kernel"}
    # Unknown machine can't be focused.
    with pytest.raises(RuntimeError, match="unknown machine"):
        s.set_focus("chatE", "lab9")


# --------------------------------------------------------------------------- #
# require_client / disconnect repoint / reporting helpers
# --------------------------------------------------------------------------- #


async def test_require_client_returns_connected_view(
        fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    client = s.clients["lab2.kernel"]
    assert s.require_client("lab2.kernel") is client
    assert s.require_client("lab2") is client
    assert s.require_client("") is client  # single machine default
    with pytest.raises(RuntimeError):
        s.require_client("ghost.machine")
    with pytest.raises(RuntimeError):
        s.require_client("lab2.user")


async def test_disconnect_primary_repoints_to_kernel(
        fake_agent_class) -> None:
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    await s.connect(host="127.0.0.1", port=6003, token="x", machine="lab5")
    await s.connect(host="127.0.0.1", port=6004, token="x", name="lab5.user")
    assert s.primary == "lab2.kernel"
    out = await s.disconnect(name="lab2.kernel")
    assert out["disconnected"] == ["lab2.kernel"]
    # Primary repoints to a live kernel-kind view, not lab5.user.
    assert s.primary == "lab5.kernel"
    assert s.client is s.clients["lab5.kernel"]
    out = await s.disconnect()
    assert s.clients == {}
    assert set(out["disconnected"]) == {"lab5.kernel", "lab5.user"}


async def test_machines_grouping_and_labels(fake_agent_class) -> None:
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-TWO"
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    await s.connect(host="127.0.0.1", port=6002, token="x", name="lab2.user")
    await s.connect(host="127.0.0.1", port=6003, token="x", machine="lab5")
    assert s.machines() == {"lab2": ["lab2.kernel", "lab2.user"],
                            "lab5": ["lab5.kernel"]}
    label = s.machine_label("lab2.kernel")
    assert label["machine"] == "lab2"
    assert label["computer_name"] == "DESKTOP-TWO"
    assert label["endpoint"] == "127.0.0.1:6001"


async def test_target_stamp(fake_agent_class) -> None:
    fake_agent_class.computer_names[("127.0.0.1", 6001)] = "DESKTOP-TWO"
    s = Session(_mk_cfg())
    await s.connect(host="127.0.0.1", port=6001, token="x", machine="lab2")
    stamp = s.target_stamp("lab2.kernel")
    assert stamp == {"view": "lab2.kernel", "machine": "lab2",
                     "computer_name": "DESKTOP-TWO",
                     "endpoint": "127.0.0.1:6001"}
    # Bare machine alias resolves to the kernel view for stamping.
    assert s.target_stamp("lab2") == stamp
    # Unresolvable / unconnected selectors return None, never raise.
    assert s.target_stamp("garbage") is None
    assert s.target_stamp("nope.kernel") is None


# --------------------------------------------------------------------------- #
# view-key helpers
# --------------------------------------------------------------------------- #


def test_view_key_split_helpers() -> None:
    assert Session.machine_of("lab2.kernel") == "lab2"
    assert Session.view_kind_of("lab2.kernel") == "kernel"
    assert Session.machine_of("DESKTOP-ABC.user") == "DESKTOP-ABC"
    assert Session.view_kind_of("DESKTOP-ABC.user") == "user"
    # Undotted keys are their own machine label.
    assert Session.machine_of("plainname") == "plainname"
    assert Session.view_kind_of("plainname") == "plainname"
