"""SymbolsApi: PDB-backed RVAs for unexported kernel globals."""

from __future__ import annotations

from pathlib import Path

from ...symbols import ensure_pdb, resolve_rvas


class SymbolsApi:
    """PDB-backed RVAs for unexported-but-symboled kernel globals
    (PiDDBCacheTable, MmUnloadedDrivers, ...). dbghelp + symbol server,
    cached under artifacts.pdb_cache."""

    def __init__(self, cache_dir: str = "", allow_download: bool = True,
                 servers: list[str] | None = None) -> None:
        self._cache_dir = cache_dir
        self._allow_download = allow_download
        self._servers = list(servers) if servers else ["https://msdl.microsoft.com/download/symbols"]

    def ensure_pdb(self, binary_path: str) -> Path:
        return ensure_pdb(binary_path, self._cache_dir, self._allow_download, self._servers)

    def resolve(self, binary_path: str, names: list[str]) -> dict[str, int]:
        """name -> RVA. Names absent from the PDB are simply missing."""
        return resolve_rvas(binary_path, names, self._cache_dir, self._allow_download,
                            self._servers)
