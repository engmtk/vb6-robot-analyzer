from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vb6_analyzer.analyzer import analyze_file  # noqa: E402
from vb6_analyzer.gui import run_gui  # noqa: E402
from vb6_analyzer.report import write_reports  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Analisador estático de executáveis VB6")
    parser.add_argument("arquivo", nargs="?", help="EXE a analisar; sem este argumento, abre a interface gráfica")
    parser.add_argument("--saida", default="relatorios", help="Pasta de saída para execução por linha de comando")
    args = parser.parse_args()
    if not args.arquivo:
        run_gui()
        return 0
    try:
        report = analyze_file(args.arquivo)
        html_path, json_path = write_reports(report, args.saida)
        print(f"Análise concluída: {html_path}")
        print(f"Dados estruturados: {json_path}")
        return 0
    except Exception as exc:
        print(f"Falha: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
