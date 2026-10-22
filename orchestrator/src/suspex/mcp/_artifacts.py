"""Shared artifact-store resolution: canonical paths + sha256 index.

v0.27: every artifact producer/consumer used to resolve ``artifacts.dir``
independently against the process cwd — two orchestrator launches with
different cwds produced two stores (``<repo>/artifacts`` vs
``orchestrator/artifacts``) and each consumer's relative-path join picked
one at random. ``config.artifacts_dir()`` now anchors relative dirs at
the repo root, and all tool-layer artifact paths funnel through
``resolve_artifact_path`` so these spellings stay equivalent everywhere:

    dumps/x.sys                                artifacts-relative (the
                                             `path` list_artifacts emits)
    artifacts/dumps/x.sys                      leading store-name prefix
    D:\\Source\\suspex0\\artifacts\\dumps\\x.sys absolute (`abs_path`)
    spill/<sha256>.bin                         spill payloads, including a
                                             spill_dir relocated outside
                                             artifacts/ by
                                             SUSPX_MCP_SPILL_DIR

``find_artifact_by_sha`` covers the WHOLE store — dumps/, ingested/,
spill/, and store_binary's ``<sha256>/`` workdirs — so ``sha256=``
lookups stop being spill-only.
"""

from __future__ import annotations

from pathlib import Path


def artifact_roots(cfg) -> list[Path]:
    """Resolved containment roots: artifacts_dir first, plus spill_dir
    when it diverges (SUSPX_MCP_SPILL_DIR can point outside artifacts/).
    """
    roots: list[Path] = []
    for r in (cfg.artifacts_dir(), cfg.spill_dir()):
        try:
            rr = Path(r).resolve()
        except OSError:
            continue
        if rr not in roots:
            roots.append(rr)
    return roots


def resolve_artifact_path(cfg, raw: str) -> Path | None:
    """Resolve one user-supplied artifact path to an absolute Path under
    a store root, or None when the input escapes every root.

    A leading component equal to a root's own name — or the literal
    ``artifacts`` — is stripped: callers keep pasting the store prefix
    the returned paths already carry (``artifacts/ingested/x.sys`` used
    to double-prefix to ``artifacts/artifacts/ingested/…``). Existence
    is NOT checked — a contained-but-missing path still resolves, and
    the caller decides between not_found and bad_arg.
    """
    if not raw:
        return None
    roots = artifact_roots(cfg)
    if not roots:
        return None
    p = Path(raw)
    if p.is_absolute():
        rp = p.resolve()
        return rp if any(r == rp or r in rp.parents for r in roots) else None
    parts = [seg for seg in p.parts if seg not in ("", ".")]
    base, rest = roots[0], parts
    if parts:
        head = parts[0].lower()
        for i, r in enumerate(roots):
            if head == r.name.lower() or (i == 0 and head == "artifacts"):
                base, rest = r, parts[1:]
                break
        else:
            # 'spill/<sha>.bin' still routes to the spill root when it's
            # relocated outside artifacts/ under a different dir name.
            if head == "spill" and len(roots) > 1:
                base, rest = roots[1], parts[1:]
    if not rest:
        return base
    cand = (base / Path(*rest)).resolve()
    return cand if any(r == cand or r in cand.parents for r in roots) else None


def find_artifact_by_sha(cfg, sha_prefix: str) -> tuple[str, str] | None:
    """sha256 prefix -> (abs_path, digest) across the whole store.

    Spill payloads are named ``<sha256>.<ext>`` so a stem-prefix glob is
    free; named artifacts (dumps/, ingested/, store_binary workdirs)
    hash through files.py's mtime-cached ``_artifact_sha256``.
    """
    pref = (sha_prefix or "").lower().strip()
    if not pref:
        return None
    from .tools.files import _artifact_sha256
    try:
        spill = Path(cfg.spill_dir())
        for p in sorted(spill.glob(pref + "*")):
            if p.is_file() and p.suffix.lstrip(".").lower() != "idx":
                return str(p), p.stem.lower()
    except OSError:
        pass
    art = Path(cfg.artifacts_dir())
    if not art.is_dir():
        return None
    for f in sorted(art.rglob("*")):
        if not f.is_file():
            continue
        try:
            digest = _artifact_sha256(f)
        except OSError:
            continue
        if digest and digest.startswith(pref):
            return str(f), digest
    return None
