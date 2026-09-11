from __future__ import annotations

import html
import json
from pathlib import Path

from .models import AnalysisReport


def write_json(report: AnalysisReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _table(headers: list[str], rows: list[list[object]], empty: str = "Nenhum item identificado") -> str:
    if not rows:
        return f'<p class="empty">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{_e(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def write_html(report: AnalysisReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    import_rows = [
        [lib.name, ", ".join(lib.functions[:30]) + (" …" if len(lib.functions) > 30 else ""), len(lib.functions)]
        for lib in report.imports
    ]
    finding_rows = [[item.category, item.value, item.confidence, item.evidence] for item in report.findings]
    capability_rows = [[item.value, item.confidence, item.evidence] for item in report.capabilities]
    section_rows = [
        [item.name, f"0x{item.virtual_address:08X}", item.virtual_size, item.raw_size, f"0x{item.characteristics:08X}"]
        for item in report.sections
    ]
    warnings = "".join(f"<li>{_e(item)}</li>" for item in report.warnings) or "<li>Nenhum alerta.</li>"
    cards = [
        ("Tecnologia", f"{report.vb_version} · confiança {report.vb_confidence}"),
        ("Arquitetura", report.architecture),
        ("Subsistema", report.subsystem),
        ("Modo VB6", f"{report.compilation_mode} · confiança {report.compilation_confidence}"),
        ("Bibliotecas", str(len(report.imports))),
        ("Evidências", str(len(report.findings))),
    ]
    card_html = "".join(f"<div class='card'><span>{_e(k)}</span><strong>{_e(v)}</strong></div>" for k, v in cards)
    document = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VB6 Robot Analyzer — {_e(report.file_name)}</title>
<style>
:root{{--bg:#f4f7fb;--panel:#fff;--ink:#182230;--muted:#667085;--brand:#155eef;--line:#dfe5ee;--warn:#9a6700}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Segoe UI,Arial,sans-serif}}
header{{background:#101828;color:white;padding:28px max(24px,calc((100% - 1180px)/2))}} header h1{{margin:0 0 6px;font-size:26px}} header p{{margin:0;color:#cbd5e1}}
main{{max-width:1180px;margin:24px auto;padding:0 20px 48px}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.card,section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 8px #1018280a}} .card{{padding:16px;min-height:92px}} .card span{{display:block;color:var(--muted);font-size:12px;margin-bottom:7px}} .card strong{{font-size:15px}}
section{{margin-top:18px;padding:20px}} h2{{font-size:18px;margin:0 0 14px}} .meta{{display:grid;grid-template-columns:150px 1fr;gap:7px 14px}} .meta dt{{color:var(--muted)}} .meta dd{{margin:0;word-break:break-all}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse}} th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{background:#f8fafc;color:#344054;position:sticky;top:0}} td:nth-child(2){{word-break:break-word}}
.warning{{border-left:4px solid #f5b700;background:#fffaeb}} .empty{{color:var(--muted)}} code{{font-family:Consolas,monospace}} footer{{color:var(--muted);margin-top:20px}}
</style></head><body>
<header><h1>VB6 Robot Analyzer</h1><p>Análise estática de {_e(report.file_name)} — o executável não foi iniciado.</p></header>
<main><div class="grid">{card_html}</div>
<section><h2>Identificação</h2><dl class="meta">
<dt>Arquivo</dt><dd>{_e(report.file_name)}</dd><dt>Tamanho</dt><dd>{report.file_size:,} bytes</dd>
<dt>SHA-256</dt><dd><code>{_e(report.sha256)}</code></dd><dt>Analisado em</dt><dd>{_e(report.analyzed_at_utc)}</dd>
<dt>Timestamp PE</dt><dd>{_e(report.compile_timestamp_utc or 'N/D — não deve ser tratado como prova de data')}</dd>
<dt>Entry point</dt><dd>{_e(report.entry_point)}</dd><dt>Image base</dt><dd>{_e(report.image_base)}</dd></dl></section>
<section class="warning"><h2>Limites e alertas</h2><ul>{warnings}</ul></section>
<section><h2>Arquitetura funcional inferida</h2>{_table(['Capacidade','Confiança','Evidência'], capability_rows)}</section>
<section><h2>DLLs e funções importadas</h2>{_table(['Biblioteca','Funções (até 30)','Total'], import_rows)}</section>
<section><h2>Artefatos encontrados</h2>{_table(['Categoria','Valor','Confiança','Origem'], finding_rows)}</section>
<section><h2>Seções PE</h2>{_table(['Seção','RVA','Tamanho virtual','Tamanho em disco','Flags'], section_rows)}</section>
<footer>Relatório gerado pelo VB6 Robot Analyzer {report.analyzer_version}. Resultados são evidências para revisão humana, não reconstrução exata do fonte.</footer>
</main></body></html>"""
    path.write_text(document, encoding="utf-8")
    return path


def write_reports(report: AnalysisReport, output_dir: str | Path) -> tuple[Path, Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stem = Path(report.file_name).stem
    return write_html(report, folder / f"{stem}-relatorio.html"), write_json(report, folder / f"{stem}-relatorio.json")
