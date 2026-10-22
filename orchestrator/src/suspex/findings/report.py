"""JSON export and (deprecated) MD/HTML report generation mixin.

Split from ``findings.py`` to keep individual modules under 600 lines.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path


class ReportMixin:
    """Mixin providing ``export_json`` and the deprecated
    ``generate_report`` MD/HTML writer on ``FindingsLedger``. Assumes the
    composite class brings :meth:`list_findings` and :meth:`evidence_for`
    from :class:`LedgerCore` / :class:`NotesEventsMixin`."""

    def export_json(self) -> str:
        findings = [f.__dict__ for f in self.list_findings()]
        for f in findings:
            f["evidence"] = [e.__dict__ for e in self.evidence_for(f["id"])]
        return json.dumps(findings, indent=2)

    # ---------------------------------------------------------------- reports ----
    # NOTE: v0.18 removes the `generate_report` MCP action; the method is
    # kept for one release so external scripts don't break, but is
    # documented as deprecated and slated for removal in the next minor.

    def generate_report(self, out_dir: str | Path, session_id: str | None = None,
                        title: str = "Suspex0 Assessment Report") -> dict[str, str]:
        """Deprecated: MD/HTML report generation. Kept for one release."""
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        findings = self.list_findings(session_id)
        lines = [f"# {title}", ""]
        lines.append(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')} | findings: {len(findings)}_")
        lines.append("")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity.lower(), 5))
        for f in findings:
            lines.append(f"## [{f.severity.upper()}] {f.title}")
            lines.append(f"*finding `{f.id}` | session `{f.session_id}` | status: {f.status}*")
            lines.append("")
            lines.append(f.description)
            ev = self.evidence_for(f.id)
            for e in ev:
                lines.append("")
                lines.append(f"**Evidence ({e.kind})**")
                lines.append("```")
                lines.append(e.content if len(e.content) < 8000 else e.content[:8000] + "\n...truncated...")
                lines.append("```")
            lines.append("")
        md = "\n".join(lines)
        md_path = out / "report.md"
        md_path.write_text(md, encoding="utf-8")
        html_parts = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            "<title>", html.escape(title), "</title>",
            "<style>body{font-family:system-ui;margin:2rem;max-width:60rem}",
            "pre{background:#f4f4f4;padding:.8rem;overflow-x:auto}",
            ".sev-high{color:#b00}.sev-critical{color:#fff;background:#b00;padding:.1rem .4rem}</style>",
            "</head><body>",
            f"<h1>{html.escape(title)}</h1>",
            f"<p>{len(findings)} findings</p>",
        ]
        for f in findings:
            html_parts.append(f"<h2 class='sev-{html.escape(f.severity.lower())}'>"
                              f"[{html.escape(f.severity.upper())}] {html.escape(f.title)}</h2>")
            html_parts.append(f"<p><em>{html.escape(f.id)} | status: {html.escape(f.status)}</em></p>")
            html_parts.append(f"<div>{html.escape(f.description)}</div>")
            for e in self.evidence_for(f.id):
                html_parts.append(f"<h4>Evidence ({html.escape(e.kind)})</h4>")
                html_parts.append(f"<pre>{html.escape(e.content[:8000])}</pre>")
        html_parts.append("</body></html>")
        html_path = out / "report.html"
        html_path.write_text("\n".join(html_parts), encoding="utf-8")
        return {"markdown": str(md_path), "html": str(html_path)}
