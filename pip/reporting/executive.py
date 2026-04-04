"""
pip/reporting/executive.py

Executive Report Generator.

Produces a board-ready HTML report (and optional PDF via WeasyPrint)
suitable for delivering to a client after a penetration test engagement.

Audience: security managers, CISOs, compliance officers.
Content:  risk verdict, business impact, top attack path in plain English,
          all paths summarised, recommended next steps.

PDF generation requires: pip install weasyprint
If WeasyPrint is not installed, the HTML report is still written and
the PDF step is silently skipped.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pip.models.attack_path import AttackPath
from pip.models.context import ScanConfig, SystemContext, UserContext


class ExecutiveReporter:
    """Generates the executive PDF/HTML report."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(
        self,
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        user_ctx: UserContext,
        scan_meta: dict,
    ) -> None:
        html = self._render_html(paths, sys_ctx, user_ctx, scan_meta)

        html_path = self.config.output_dir / "executive_report.html"
        html_path.write_text(html, encoding="utf-8")

        self._try_pdf(html, self.config.output_dir / "executive_report.pdf")

    # ── HTML rendering ────────────────────────────────────────────────────────

    def _render_html(
        self,
        paths: list[AttackPath],
        sys_ctx: SystemContext,
        user_ctx: UserContext,
        scan_meta: dict,
    ) -> str:
        top = paths[0] if paths else None
        risk = top.score_label if top else "NONE"
        root_possible = bool(paths)

        risk_colors = {
            "CRITICAL": ("#dc2626", "#fef2f2"),
            "HIGH":     ("#ea580c", "#fff7ed"),
            "MEDIUM":   ("#d97706", "#fffbeb"),
            "LOW":      ("#16a34a", "#f0fdf4"),
            "NONE":     ("#6b7280", "#f9fafb"),
        }
        risk_fg, risk_bg = risk_colors.get(risk, risk_colors["NONE"])

        path_rows = self._render_path_rows(paths)
        top_path_section = self._render_top_path(top)
        recommendations = self._render_recommendations(paths, sys_ctx)

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PIP Executive Report — {sys_ctx.hostname}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 14px; color: #1f2937; background: #fff; line-height: 1.6; }}
    .page {{ max-width: 900px; margin: 0 auto; padding: 48px 40px; }}
    .header {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 24px; margin-bottom: 32px; }}
    .header h1 {{ font-size: 22px; font-weight: 600; color: #111827; }}
    .header .meta {{ font-size: 12px; color: #6b7280; margin-top: 6px; }}
    .risk-banner {{ background: {risk_bg}; border-left: 4px solid {risk_fg};
                    padding: 20px 24px; margin-bottom: 32px; border-radius: 4px; }}
    .risk-banner .label {{ font-size: 11px; font-weight: 600; color: {risk_fg};
                           letter-spacing: .06em; text-transform: uppercase; }}
    .risk-banner .value {{ font-size: 32px; font-weight: 700; color: {risk_fg}; line-height: 1.2; }}
    .risk-banner .sub {{ font-size: 13px; color: #374151; margin-top: 6px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
    .metric {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px 16px; }}
    .metric .num {{ font-size: 24px; font-weight: 600; color: #111827; }}
    .metric .lbl {{ font-size: 11px; color: #6b7280; margin-top: 2px; }}
    h2 {{ font-size: 16px; font-weight: 600; color: #111827;
          border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; margin: 28px 0 14px; }}
    .path-box {{ background: #fafafa; border: 1px solid #e5e7eb; border-radius: 6px;
                 padding: 18px 20px; margin-bottom: 16px; }}
    .path-box .path-title {{ font-weight: 600; font-size: 14px; margin-bottom: 8px; }}
    .path-box .badge {{ display: inline-block; font-size: 11px; font-weight: 600;
                        padding: 2px 8px; border-radius: 12px; margin-right: 6px; }}
    .badge-critical {{ background: #fef2f2; color: #dc2626; }}
    .badge-verified  {{ background: #f0fdf4; color: #16a34a; }}
    .badge-unverified{{ background: #f9fafb; color: #6b7280; }}
    ol.steps {{ padding-left: 20px; margin-top: 10px; }}
    ol.steps li {{ margin-bottom: 4px; font-size: 13px; }}
    ol.steps li code {{ background: #f3f4f6; padding: 1px 6px; border-radius: 3px;
                        font-family: monospace; font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
    th {{ background: #f9fafb; font-weight: 600; text-align: left;
          padding: 8px 12px; border: 1px solid #e5e7eb; }}
    td {{ padding: 8px 12px; border: 1px solid #e5e7eb; }}
    tr:hover td {{ background: #f9fafb; }}
    .rec {{ background: #eff6ff; border-left: 3px solid #3b82f6;
            padding: 12px 16px; margin-bottom: 10px; border-radius: 0 4px 4px 0; font-size: 13px; }}
    .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb;
               font-size: 11px; color: #9ca3af; }}
  </style>
</head>
<body>
<div class="page">
  <div class="header">
    <h1>PrivEsc Intelligence Platform — Executive Report</h1>
    <div class="meta">
      Generated: {ts} &nbsp;|&nbsp;
      Target: <strong>{sys_ctx.hostname}</strong> &nbsp;|&nbsp;
      OS: {sys_ctx.os_name} {sys_ctx.os_version} &nbsp;|&nbsp;
      Kernel: {sys_ctx.kernel_version} &nbsp;|&nbsp;
      Environment: {sys_ctx.environment_type.value.replace('_', ' ').title()} &nbsp;|&nbsp;
      Scan mode: {scan_meta.get('mode', 'unknown')} &nbsp;|&nbsp;
      Duration: {scan_meta.get('duration_seconds', 0):.0f}s
    </div>
  </div>

  <div class="risk-banner">
    <div class="label">Overall Risk Level</div>
    <div class="value">{risk}</div>
    <div class="sub">
      Root Access Possible: <strong>{'YES' if root_possible else 'NO'}</strong>
      &nbsp;—&nbsp;
      {f'The highest-scoring path scored {top.composite_score}/10.' if top else 'No exploitable paths were identified.'}
    </div>
  </div>

  <div class="metrics">
    <div class="metric"><div class="num">{len(paths)}</div><div class="lbl">attack paths found</div></div>
    <div class="metric"><div class="num">{sum(1 for p in paths if p.verified)}</div><div class="lbl">paths verified</div></div>
    <div class="metric"><div class="num">{scan_meta.get('findings_count', 0)}</div><div class="lbl">raw findings</div></div>
    <div class="metric"><div class="num">{scan_meta.get('duration_seconds', 0):.0f}s</div><div class="lbl">scan duration</div></div>
  </div>

  {top_path_section}

  <h2>All Attack Paths</h2>
  {'<p style="color:#6b7280">No attack paths identified.</p>' if not paths else f'''
  <table>
    <tr><th>#</th><th>Method</th><th>Score</th><th>Verified</th><th>Time</th><th>MITRE</th></tr>
    {path_rows}
  </table>'''}

  {recommendations}

  <div class="footer">
    PIP v2.0.0 — PrivEsc Intelligence Platform &nbsp;|&nbsp;
    This report is confidential and intended solely for the authorised recipient.
    Unauthorised disclosure is prohibited.
  </div>
</div>
</body>
</html>"""

    def _render_top_path(self, top: AttackPath | None) -> str:
        if not top:
            return ""
        verified_badge = (
            '<span class="badge badge-verified">VERIFIED</span>'
            if top.verified
            else '<span class="badge badge-unverified">UNVERIFIED</span>'
        )
        steps_html = "".join(
            f"<li>{s.description}"
            + (f" <code>{s.command[:80]}</code>" if s.command else "")
            + (f" <em>(wait ~{s.wait_seconds}s)</em>" if s.wait_seconds else "")
            + "</li>"
            for s in top.steps
        )
        mitre = ", ".join(top.mitre_ids) or "n/a"
        return f"""
  <h2>Recommended Attack Path</h2>
  <div class="path-box">
    <div class="path-title">
      {top.title}
      <span class="badge badge-critical">{top.composite_score}/10</span>
      {verified_badge}
    </div>
    <div style="font-size:12px;color:#6b7280;margin-bottom:10px">
      MITRE ATT&amp;CK: {mitre} &nbsp;|&nbsp;
      Estimated time: ~{top.estimated_time_seconds}s &nbsp;|&nbsp;
      Stealth: {'HIGH' if top.stealth >= 0.7 else 'MEDIUM' if top.stealth >= 0.4 else 'LOW'}
    </div>
    <ol class="steps">{steps_html}</ol>
    {f'<p style="margin-top:12px;font-size:13px;color:#374151">{top.narrative}</p>' if top.narrative else ''}
  </div>"""

    @staticmethod
    def _render_path_rows(paths: list[AttackPath]) -> str:
        rows = []
        for i, p in enumerate(paths, 1):
            verified = "✓ YES" if p.verified else "—"
            mitre = ", ".join(p.mitre_ids[:2]) or "—"
            t = f"~{p.estimated_time_seconds}s" if p.estimated_time_seconds else "—"
            rows.append(
                f"<tr><td>{i}</td><td>{p.title[:60]}</td>"
                f"<td><strong>{p.composite_score:.1f}</strong></td>"
                f"<td>{verified}</td><td>{t}</td><td>{mitre}</td></tr>"
            )
        return "".join(rows)

    @staticmethod
    def _render_recommendations(paths: list[AttackPath], sys_ctx: SystemContext) -> str:
        if not paths:
            return ""
        items = []
        seen_mitre: set[str] = set()
        for path in paths[:5]:
            for mid in path.mitre_ids:
                if mid not in seen_mitre:
                    seen_mitre.add(mid)
                    items.append(f'<div class="rec">Remediate findings mapped to <strong>{mid}</strong>. '
                                 f'See the Blue Team report for exact remediation commands.</div>')
        items.append('<div class="rec">Review the full technical report (technical_report.json) '
                     'and blue team hardening checklist (blue_team_report.json) for step-by-step remediation.</div>')
        items.append('<div class="rec">Re-run PIP after remediation to confirm all paths are closed.</div>')
        return f"<h2>Recommended Next Steps</h2>{''.join(items)}"

    @staticmethod
    def _try_pdf(html: str, out_path: Path) -> None:
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html).write_pdf(str(out_path))
        except ImportError:
            pass  # WeasyPrint optional
        except Exception:
            pass
