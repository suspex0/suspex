"""JVM bootstrap + shared-project state for the pyghidra backend.

One process = one JVM = one Ghidra project hosting N programs. The
``PROGRAMS`` registry maps the shim's ``binary_name`` (a program's
name inside the project) to its live ``Program``/``FlatProgramAPI``
handles, the backing ``DomainFile``, and the original import path.

Everything Ghidra/JPype is imported lazily AFTER ``start_jvm`` —
``import ghidra`` before the JVM is up fails, and ``import pyghidra``
before ``GHIDRA_INSTALL_DIR`` is set fails, so module import order is
load-bearing here. Keep imports inside functions.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

LOG_PREFIX = "pyghidra_ext"


def _log(msg: str) -> None:
    import sys
    print(f"{LOG_PREFIX}: {msg}", file=sys.stderr, flush=True)


def _j(obj: Any) -> str:
    return json.dumps(obj)


class GhidraState:
    """Owns the JVM, the shared project, and the program registry."""

    def __init__(self) -> None:
        self.jvm_started = False
        self.project = None                    # ghidra.base.project.GhidraProject
        self.project_dir: Path | None = None
        self.project_name: str = ""
        # binary_name -> {program, flat, df, path, imported_at}
        self.programs: dict[str, dict[str, Any]] = {}
        # Ghidra program ops are NOT thread-safe across objects; one
        # re-entrant lock serializes all tool execution (matches the
        # single-writer reality of a JVM process anyway).
        self.lock = threading.RLock()
        self._decomp: dict[str, Any] = {}      # binary_name -> DecompInterface

    # ------------------------------------------------------------ jvm ----

    def start_jvm(self, ghidra_dir: str = "", java_home: str = "",
                  heap_mb: int = 8192, verbose: bool = False) -> None:
        """Boot JPype + Ghidra classes. Idempotent."""
        if self.jvm_started:
            return
        if ghidra_dir:
            os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
        if java_home:
            os.environ["JAVA_HOME"] = java_home
        if not os.environ.get("GHIDRA_INSTALL_DIR"):
            raise RuntimeError(
                "GHIDRA_INSTALL_DIR not set and ghidra_dir not configured. "
                "Install Ghidra and set ghidra.ghidra_dir in the suspex0 "
                "config (or export GHIDRA_INSTALL_DIR).")
        gdir = Path(os.environ["GHIDRA_INSTALL_DIR"])
        if not gdir.is_dir():
            raise RuntimeError(
                f"GHIDRA_INSTALL_DIR {str(gdir)!r} is not a directory — "
                "point ghidra.ghidra_dir at a real Ghidra install.")
        try:
            import pyghidra  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "pyghidra not importable in this interpreter — install it "
                "into the backend env (orchestrator: `uv sync --extra "
                "ghidra`, or `uv pip install pyghidra`).") from exc

        started = False
        # Preferred path: explicit launcher so -Xmx is honored.
        try:
            from pyghidra.launcher import HeadlessPyGhidraLauncher
            vmargs = [f"-Xmx{int(heap_mb)}m"] if heap_mb else None
            try:
                launcher = HeadlessPyGhidraLauncher(
                    verbose=verbose, vmargs=vmargs)
            except TypeError:
                launcher = HeadlessPyGhidraLauncher(verbose=verbose)
            launcher.start()
            started = True
        except Exception as exc:  # noqa: BLE001 - fall back to pyghidra.start
            _log(f"HeadlessPyGhidraLauncher failed ({exc}); "
                 "trying pyghidra.start()")
        if not started:
            import pyghidra
            pyghidra.start(verbose=verbose)
        try:
            import jpype
            if not jpype.isJVMStarted():
                raise RuntimeError("JPype reported JVM not started")
        except ImportError:
            pass
        self.jvm_started = True
        _log("JVM started")

    # ---------------------------------------------------------- project ----

    def open_project(self, project_dir: str, name: str) -> None:
        """Open (or create) the shared Ghidra project."""
        self.start_jvm()
        from ghidra.base.project import GhidraProject
        pdir = Path(project_dir)
        pdir.mkdir(parents=True, exist_ok=True)
        project = None
        lock_budget_s = 90.0
        lock_deadline = time.time() + lock_budget_s
        saw_other_error = False
        while project is None and time.time() < lock_deadline:
            try:
                project = GhidraProject.openProject(str(pdir), name)
                break
            except Exception as exc:  # noqa: BLE001
                # LockException = a live (or just-killed) backend still
                # holds the project — retry, NEVER createProject on a
                # locked existing project (it deletes it and asserts).
                if "LockException" not in type(exc).__name__ \
                        and "LockException" not in str(exc):
                    _log(f"openProject({name}) failed ({exc}); creating")
                    saw_other_error = True
                    break
                # A killed JVM leaves the .lock marker file behind; the
                # OS channel lock lives on .lock~ and dies with its
                # holder. Order matters: only clear the .lock marker
                # once .lock~ is gone or removable — deleting it while
                # a LIVE holder owns the project would invite a second
                # writer in. Our backend is the only writer of this
                # dedicated project dir, so this is crash recovery.
                try:
                    (pdir / f"{name}.lock~").unlink(missing_ok=True)
                    holder_dead = True
                except OSError:
                    holder_dead = False  # still held by a live process
                if holder_dead:
                    try:
                        (pdir / f"{name}.lock").unlink(missing_ok=True)
                    except OSError:
                        pass
                time.sleep(5)
        if project is None:
            if saw_other_error:
                try:
                    project = GhidraProject.createProject(
                        str(pdir), name, False)
                except TypeError:
                    project = GhidraProject.createProject(str(pdir), name)
            else:
                raise RuntimeError(
                    f"ghidra project {pdir / name} is still locked after "
                    f"{lock_budget_s:.0f}s — another backend is holding "
                    "it; close it and retry")
        self.project = project
        self.project_dir = pdir
        self.project_name = name
        _log(f"project open: {pdir}/{name}")

    # ---------------------------------------------------------- monitor ----

    @staticmethod
    def monitor():
        from ghidra.util.task import TaskMonitor
        return TaskMonitor.DUMMY

    # ---------------------------------------------------------- programs ----

    @staticmethod
    def _safe_program_name(name: str) -> str:
        """Program names live inside the project tree — keep to a sane
        charset (mirrors the bridge's session-name rule)."""
        return re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[:64] or "prog"

    def import_binary(self, binary_path: str, name: str = "",
                      analyze: bool = True) -> dict:
        """Import ``binary_path`` into the shared project and register it.

        Returns ``{binary_name, program, path, analyzed}``. If a program
        of the same name is already registered (or sits in the project),
        it is adopted instead of re-imported.
        """
        assert self.project is not None, "open_project first"
        p = Path(binary_path).resolve()
        if not p.is_file():
            raise RuntimeError(f"import_binary: no such file: {binary_path}")
        pname = self._safe_program_name(name or p.stem)
        if pname in self.programs:
            st = self.programs[pname]
            return {"binary_name": pname, "path": st["path"],
                    "program": pname, "adopted": True,
                    "analyzed": self.is_analyzed(pname)}
        # Name already in the project (imported by this or a previous
        # backend)? Adopt it — Ghidra's importer does NOT throw
        # DuplicateNameException for us to catch; it silently renames
        # to <name>.0 and we'd pile up copies of the same binary.
        adopted = self._adopt(pname)
        if adopted is not None:
            self.programs[pname] = {
                "program": adopted, "flat": self._flat(adopted),
                "df": self._safe(lambda: adopted.getDomainFile(), None),
                "path": str(p), "imported_at": time.time()}
            return {"binary_name": pname, "path": str(p),
                    "program": pname, "adopted": True,
                    "analyzed": self.is_analyzed(pname)}
        from java.io import File
        from java.lang import Object as _JObject
        from ghidra.app.util.importer import AutoImporter, MessageLog
        with self.lock:
            # AutoImporter is the canonical import-into-project path:
            # it loads, binds AND can save the domain file in one shot.
            # (Ghidra 12.1.4: project.importProgram returns an unbound
            # ProgramDB — createFile on it throws "Object is busy and
            # can not be saved".) consumer must be a real java.lang.Object
            # — jpype won't coerce a Python object into the signature.
            #
            # The project file takes the SOURCE filename and cannot be
            # renamed while held open (FileInUseException survives even
            # a full release). So when the requested name differs, stage
            # a hardlink/copy named pname and import that instead —
            # importByUsingBestGuess detects format by content, not ext.
            import_path = p
            tmp_dir = None
            if pname and pname != p.name:
                import shutil
                import tempfile
                tmp_dir = tempfile.mkdtemp(prefix="suspx_ghidra_")
                staged = Path(tmp_dir) / pname
                try:
                    os.link(p, staged)
                except OSError:
                    shutil.copy2(p, staged)
                import_path = staged
            try:
                consumer = _JObject()
                try:
                    results = AutoImporter.importByUsingBestGuess(
                        File(str(import_path)), self.project.getProject(),
                        "/", consumer, MessageLog(), self.monitor())
                except Exception as exc:  # noqa: BLE001 - name clash means
                    # the program already lives in the project: adopt it
                    if "DuplicateName" in type(exc).__name__ \
                            or "DuplicateName" in str(exc):
                        adopted = self._adopt(pname)
                        if adopted is not None:
                            self.programs[pname] = {
                                "program": adopted, "flat": self._flat(adopted),
                                "df": adopted.getDomainFile(), "path": str(p),
                                "imported_at": time.time()}
                            return {"binary_name": pname, "path": str(p),
                                    "program": pname, "adopted": True,
                                    "analyzed": self.is_analyzed(pname)}
                    raise
                try:
                    program = results.getPrimaryDomainObject(consumer)
                except Exception:  # noqa: BLE001
                    program = results.getPrimaryDomainObject()
                # Persist the fresh import into the project file.
                results.save(self.monitor())
                df = program.getDomainFile()
                if df is not None:
                    pname = df.getName()
            finally:
                if tmp_dir is not None:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            flat = self._flat(program)
            self.programs[pname] = {
                "program": program, "flat": flat, "df": df,
                "path": str(p), "imported_at": time.time(),
            }
            if analyze:
                self.analyze(pname)
            # Checkpoint analysis results — headless Ghidra never
            # auto-saves.
            self._save_program(pname)
        return {"binary_name": pname, "path": str(p), "program": pname,
                "adopted": False, "analyzed": self.is_analyzed(pname)}

    def _program_from_domain_file(self, df: Any, pname: str):
        """Extract a live ``Program`` from an importProgram() return.

        Import signatures vary across Ghidra versions (DomainFile vs
        Program); probe the shape rather than hard-coding one.
        """
        # Already a Program?
        if hasattr(df, "getFunctionManager") and hasattr(df, "getListing"):
            return df
        from java.lang import Object as _JObject
        try:
            program = df.getDomainObject(
                _JObject(), True, True, self.monitor())
            if program is not None:
                return program
        except TypeError:
            pass
        # Last resort: open by name through the project.
        try:
            return self.project.openProgram(pname, False, self.monitor())
        except TypeError:
            return self.project.openProgram(pname)

    @staticmethod
    def _flat(program: Any):
        from ghidra.program.flatapi import FlatProgramAPI
        return FlatProgramAPI(program)

    def get(self, binary_name: str) -> dict:
        st = self.programs.get(binary_name)
        if st is not None:
            return st
        # Adoption path: program exists in the project but this process
        # never imported it (backend restarted; the project persisted).
        if self.project is not None:
            program = self._adopt(binary_name)
            if program is not None:
                st = {"program": program, "flat": self._flat(program),
                      "df": self._safe(lambda: program.getDomainFile(), None),
                      "path": "", "imported_at": time.time()}
                self.programs[binary_name] = st
                return st
        raise RuntimeError(
            f"unknown program {binary_name!r}; known: "
            + (", ".join(sorted(self.programs)) or "none")
            + " — import via ghidra_manage(action='open', path=...)")

    def _adopt(self, binary_name: str):
        """Try to open a project-resident program by name."""
        try:
            from java.lang import Object as _JObject
            consumer = _JObject()
            root = self._root()
            df = root.getFile(binary_name)
            if df is None:
                return None
            try:
                return df.getDomainObject(
                    consumer, True, True, self.monitor())
            except TypeError:
                return df.getReadOnlyDomainObject(
                    consumer, True, self.monitor())
        except Exception as exc:  # noqa: BLE001
            _log(f"adopt({binary_name}) failed: {exc}")
            return None

    def _root(self):
        """Root folder, refreshed so renames/deletes from this process
        or a predecessor backend don't leave ghost entries."""
        try:
            self.project.getProjectData().refreshRootFolder()
        except Exception:  # noqa: BLE001 - refresh is best-effort
            pass
        return self.project.getProjectData().getRootFolder()

    def list_programs(self) -> list[dict]:
        """Project-side listing — includes programs imported by a dead
        predecessor backend (the project file outlives the process)."""
        out: list[dict] = []
        seen: set[str] = set()
        for name, st in self.programs.items():
            prog = st["program"]
            out.append({"binary_name": name,
                        "path": st.get("path", ""),
                        "in_registry": True,
                        "analyzing": self.is_analyzing(name),
                        "image_base": str(prog.getImageBase()),
                        "language": str(prog.getLanguageID()),
                        "executable_format": self._safe(
                            lambda: str(prog.getExecutableFormat()))})
            seen.add(name)
            df = st.get("df") or self._safe(
                lambda: prog.getDomainFile(), None)
            if df is not None:
                seen.add(self._safe(lambda: df.getName(), ""))
        if self.project is not None:
            try:
                for f in self._root().getFiles():
                    nm = f.getName()
                    if nm in seen:
                        continue
                    out.append({"binary_name": nm,
                                "path": "",
                                "in_registry": False,
                                "analyzing": False,
                                "image_base": "", "language": "",
                                "executable_format": ""})
            except Exception:  # noqa: BLE001
                pass
        return out

    @staticmethod
    def _safe(fn, default: str = "") -> Any:
        try:
            return fn()
        except Exception:  # noqa: BLE001
            return default

    # ---------------------------------------------------------- analysis ----

    def _analysis_mgr(self, program: Any):
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        return AutoAnalysisManager.getAnalysisManager(program)

    def analyze(self, binary_name: str) -> None:
        st = self.get(binary_name)
        program = st["program"]
        try:
            mgr = self._analysis_mgr(program)
            mgr.reAnalyzeAll(None)
            # Ghidra 12: startAnalysis runs the queue; waitForAnalysis
            # blocks until it drains (headless-friendly).
            mgr.startAnalysis(self.monitor())
            try:
                mgr.waitForAnalysis(None, self.monitor())
            except Exception:  # noqa: BLE001 - best-effort wait
                pass
        except Exception:  # noqa: BLE001 - flat fallback
            st["flat"].analyzeAll(program)

    def is_analyzing(self, binary_name: str) -> bool:
        try:
            st = self.get(binary_name)
            return bool(self._analysis_mgr(st["program"]).isAnalyzing())
        except Exception:  # noqa: BLE001
            return False

    def is_analyzed(self, binary_name: str) -> bool:
        try:
            st = self.get(binary_name)
            fm = st["program"].getFunctionManager()
            return int(fm.getFunctionCount()) > 0 or not self.is_analyzing(
                binary_name)
        except Exception:  # noqa: BLE001
            return False

    def _save_program(self, binary_name: str) -> bool:
        """Flush a program's domain file into the shared project.

        Ghidra headless does not auto-save — every mutation (import,
        analyze, rename) is in-memory until df.save()/project.save()."""
        st = self.programs.get(binary_name)
        if st is None:
            return False
        try:
            df = st.get("df") or st["program"].getDomainFile()
            df.save(self.monitor())
            return True
        except Exception:  # noqa: BLE001
            # GhidraProject.save(Program) only works for programs already
            # bound to a location — for unbound ones it's a
            # ReadOnlyException; createFile is the real bind path.
            try:
                prog = st["program"]
                root = self._root()
                existing = root.getFile(binary_name)
                if existing is not None:
                    existing.save(self.monitor())
                    st["df"] = existing
                else:
                    st["df"] = root.createFile(
                        binary_name, prog, self.monitor())
                return True
            except Exception:  # noqa: BLE001
                return False

    # ---------------------------------------------------------- addresses ----

    @staticmethod
    def _signed64(off: int) -> int:
        """Reinterpret an unsigned 64-bit offset as a Java long.

        jpype only converts Python ints into *signed* longs; kernel
        addresses >= 0x8000000000000000 must wrap negative or the
        getAddress call overflows."""
        off &= 0xFFFFFFFFFFFFFFFF
        return off - (1 << 64) if off >= (1 << 63) else off

    @staticmethod
    def to_addr(program: Any, value: Any):
        """Parse ``value`` (int / '0x…' / decimal str / 'sym+0xN') to an
        Address on ``program``'s default space."""
        if isinstance(value, int):
            off = GhidraState._signed64(value)
            return program.getAddressFactory() \
                .getDefaultAddressSpace().getAddress(off)
        s = str(value).strip()
        # symbol(+0xoff) spellings resolve through the symbol table.
        m = re.match(r"^([A-Za-z_][\w.$@?]*)((?:\+|-)0x[0-9a-fA-F]+|\+|-\d+)?$", s)
        if m and not re.match(r"^0x[0-9a-fA-F]+$", s):
            sym_name, delta = m.group(1), m.group(2)
            st = program.getSymbolTable()
            try:
                syms = st.getGlobalSymbols(sym_name)
            except Exception:  # noqa: BLE001
                syms = []
            try:
                syms = list(syms)
            except TypeError:
                syms = [s for s in syms]
            if syms:
                addr = syms[0].getAddress()
                if delta:
                    addr = addr.add(int(delta.replace("+", ""), 0)
                                    if delta.startswith("+")
                                    else -int(delta[1:], 0))
                return addr
        space = program.getAddressFactory().getDefaultAddressSpace()
        s64 = GhidraState._signed64
        if s.lower().startswith("0x"):
            return space.getAddress(s64(int(s, 16)))
        if re.match(r"^[0-9a-fA-F]+$", s) and not s.isdigit():
            return space.getAddress(s64(int(s, 16)))
        return space.getAddress(s64(int(s, 0)))

    def get_function(self, program: Any, name_or_address: Any):
        """Resolve a function by name or address (inclusive contain)."""
        fm = program.getFunctionManager()
        if isinstance(name_or_address, str) and not re.match(
                r"^(0x)?[0-9a-fA-F]+(\+\s*0x?[0-9a-fA-F]+)?$",
                name_or_address.strip()):
            # name lookup
            try:
                funcs = fm.getFunctions(name_or_address)
                funcs = list(funcs)
                if funcs:
                    return funcs[0]
            except Exception:  # noqa: BLE001
                pass
            it = fm.getFunctions(True)
            while it.hasNext():
                f = it.next()
                if f.getName() == name_or_address:
                    return f
            return None
        addr = self.to_addr(program, name_or_address)
        f = fm.getFunctionAt(addr)
        if f is None:
            f = fm.getFunctionContaining(addr)
        return f


STATE = GhidraState()
