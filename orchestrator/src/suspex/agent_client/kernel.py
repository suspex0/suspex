"""Kernel-registry (Registry service) methods split off from AgentClient."""

from __future__ import annotations

from typing import Any

from ..generated import suspex_pb2 as pb
from .wire import status_dict


class KernelMixin:
    async def reg_get(self, hive: str, subkey: str, value: str,
                      wow64_32: bool = False,
                      impersonate: str = "",
                      raw_hex: bool = False) -> dict[str, Any]:
        # v0.17 A-3: default response is shape-driven — one canonical
        # ``value`` field per REG_ type — so the caller doesn't ship 4x
        # redundant renderings on the wire when they only wanted the
        # string. ``raw_hex=True`` restores the full historical shape
        # (`hex` + `str` + `qword` + `multi_sz` all present) for the
        # rare caller that needs to inspect every rendering (e.g. a
        # forensic dump of a suspicious value).
        if self.registry is None:
            raise RuntimeError("registry service unavailable (agent < v4?)")
        req = pb.RegGetRequest(hive=hive, subkey=subkey, value=value,
                               wow64_32=wow64_32, impersonate=impersonate)
        msg = await self._call(self.registry.Get, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)

        size = len(msg.data)
        rtype = int(msg.type)

        if raw_hex:
            # Historical wide response — every rendering surfaced.
            return {
                "type": rtype, "size": size, "hex": msg.data.hex(),
                "str": msg.data_str, "qword": msg.data_qword,
                "multi_sz": list(msg.data_multi_sz),
            }

        # Shape-driven: pick the one rendering that matches the type.
        # REG_ type integers per winreg.h:
        #   1 REG_SZ, 2 REG_EXPAND_SZ, 3 REG_BINARY, 4 REG_DWORD,
        #   5 REG_DWORD_BIG_ENDIAN, 6 REG_LINK, 7 REG_MULTI_SZ, 11 REG_QWORD
        if rtype in (1, 2):        # REG_SZ / REG_EXPAND_SZ
            return {"type": rtype, "size": size, "value": msg.data_str}
        if rtype in (4, 5, 11):    # REG_DWORD / REG_DWORD_BE / REG_QWORD
            return {"type": rtype, "size": size, "value": int(msg.data_qword)}
        if rtype == 7:             # REG_MULTI_SZ
            return {"type": rtype, "size": size,
                    "value": list(msg.data_multi_sz)}
        # REG_BINARY, REG_NONE, REG_LINK, or any unknown type — hex is the
        # only lossless rendering.
        return {"type": rtype, "size": size, "hex": msg.data.hex()}

    async def reg_set(self, hive: str, subkey: str, value: str, reg_type: int,
                      data: bytes, wow64_32: bool = False,
                      create_subkey: bool = False,
                      impersonate: str = "") -> dict[str, Any]:
        if self.registry is None:
            raise RuntimeError("registry service unavailable (agent < v4?)")
        req = pb.RegSetRequest(hive=hive, subkey=subkey, value=value, type=reg_type,
                               data=data, wow64_32=wow64_32,
                               create_subkey=create_subkey, impersonate=impersonate)
        return status_dict(await self._call(self.registry.Set, req))

    async def reg_enum(self, hive: str, subkey: str, wow64_32: bool = False,
                       want_subkeys: bool = True, want_values: bool = True,
                       impersonate: str = "") -> dict[str, Any]:
        if self.registry is None:
            raise RuntimeError("registry service unavailable (agent < v4?)")
        req = pb.RegEnumRequest(hive=hive, subkey=subkey, wow64_32=wow64_32,
                                want_subkeys=want_subkeys, want_values=want_values,
                                impersonate=impersonate)
        msg = await self._call(self.registry.Enum, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "subkeys": list(msg.subkeys),
            "values": [{"name": v.name, "type": v.type, "size": v.size} for v in msg.values],
        }

    async def reg_delete(self, hive: str, subkey: str, value: str = "",
                         recursive: bool = False,
                         wow64_32: bool = False,
                         impersonate: str = "") -> dict[str, Any]:
        if self.registry is None:
            raise RuntimeError("registry service unavailable (agent < v4?)")
        req = pb.RegDeleteRequest(hive=hive, subkey=subkey, value=value,
                                  recursive=recursive, wow64_32=wow64_32,
                                  impersonate=impersonate)
        return status_dict(await self._call(self.registry.Delete, req))
