from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyzer import analyze_file
from .models import AnalysisReport
from .report import write_reports


class AnalyzerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("VB6 Gambeta Master - Analisador de executáveis legados")
        self.geometry("1120x720")
        self.minsize(850, 560)
        self.report: AnalysisReport | None = None
        self.selected_file = tk.StringVar()
        self.status = tk.StringVar(value="Selecione um executável para iniciar.")
        self._configure_style()
        self._build()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", foreground="#667085")
        style.configure("Treeview", rowheight=25)

    def _build(self) -> None:
        header = ttk.Frame(self, padding=(22, 18))
        header.pack(fill="x")
        ttk.Label(header, text="VB6 Gambeta Master - Analisador de executáveis legados", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Inventário estático de executáveis legados — nenhum EXE analisado é executado.", style="Sub.TLabel").pack(anchor="w", pady=(3, 14))

        chooser = ttk.Frame(header)
        chooser.pack(fill="x")
        ttk.Entry(chooser, textvariable=self.selected_file).pack(side="left", fill="x", expand=True)
        ttk.Button(chooser, text="Selecionar EXE", command=self._choose).pack(side="left", padx=(8, 0))
        self.analyze_button = ttk.Button(chooser, text="Analisar", command=self._start_analysis)
        self.analyze_button.pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(chooser, text="Exportar relatório", command=self._export, state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=22, pady=(0, 14))
        self.summary = self._text_tab("Resumo")
        self.dependencies = self._tree_tab("Dependências", ("biblioteca", "funções"), (230, 760))
        self.artifacts = self._tree_tab("Artefatos", ("categoria", "valor", "confiança"), (180, 650, 100))
        self.sections = self._tree_tab("Seções PE", ("nome", "rva", "virtual", "disco"), (160, 160, 160, 160))
        self.strings = self._text_tab("Strings recuperadas")

        status_bar = ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=(8, 5))
        status_bar.pack(fill="x", side="bottom")

    def _text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="word", font=("Consolas", 10), padx=12, pady=12, borderwidth=0)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.configure(state="disabled")
        return text

    def _tree_tab(self, title: str, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in zip(columns, widths):
            tree.heading(column, text=column.replace("_", " ").title())
            tree.column(column, width=width, minwidth=80)
        y_scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x_scroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def _choose(self) -> None:
        selected = filedialog.askopenfilename(title="Selecione o executável", filetypes=[("Executável Windows", "*.exe"), ("Todos os arquivos", "*.*")])
        if selected:
            self.selected_file.set(selected)

    def _start_analysis(self) -> None:
        value = self.selected_file.get().strip()
        if not value:
            messagebox.showwarning("Arquivo necessário", "Selecione um arquivo .exe.")
            return
        self.analyze_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.status.set("Analisando estaticamente…")
        threading.Thread(target=self._analyze_worker, args=(value,), daemon=True).start()

    def _analyze_worker(self, value: str) -> None:
        try:
            report = analyze_file(value)
            self.after(0, lambda: self._show_report(report))
        except Exception as exc:  # UI boundary: present controlled failure to user.
            self.after(0, lambda: self._show_error(str(exc)))

    def _show_error(self, message: str) -> None:
        self.analyze_button.configure(state="normal")
        self.status.set("A análise falhou.")
        messagebox.showerror("Falha na análise", message)

    def _replace_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        tree.delete(*tree.get_children())

    def _show_report(self, report: AnalysisReport) -> None:
        self.report = report
        summary = [
            f"Arquivo: {report.file_name}",
            f"Tamanho: {report.file_size:,} bytes",
            f"SHA-256: {report.sha256}",
            "",
            f"PE válido: {'sim' if report.is_pe else 'não'}",
            f"Tecnologia: {report.vb_version} (confiança {report.vb_confidence})",
            f"Arquitetura: {report.architecture}",
            f"Subsistema: {report.subsystem}",
            f"Modo de compilação: {report.compilation_mode}",
            "",
            "CAPACIDADES INFERIDAS",
        ]
        summary.extend(f"- {item.value} [{item.confidence}] — {item.evidence}" for item in report.capabilities)
        summary.extend(["", "ALERTAS"])
        summary.extend(f"- {warning}" for warning in report.warnings)
        self._replace_text(self.summary, "\n".join(summary))
        self._replace_text(self.strings, "\n".join(report.strings))

        for tree in (self.dependencies, self.artifacts, self.sections):
            self._clear_tree(tree)
        for item in report.imports:
            self.dependencies.insert("", "end", values=(item.name, ", ".join(item.functions)))
        for item in report.findings:
            self.artifacts.insert("", "end", values=(item.category, item.value, item.confidence))
        for item in report.sections:
            self.sections.insert("", "end", values=(item.name, f"0x{item.virtual_address:08X}", item.virtual_size, item.raw_size))

        self.analyze_button.configure(state="normal")
        self.export_button.configure(state="normal")
        self.status.set(f"Concluído: {len(report.imports)} DLLs e {len(report.findings)} evidências encontradas.")

    def _export(self) -> None:
        if not self.report:
            return
        folder = filedialog.askdirectory(title="Escolha a pasta dos relatórios")
        if not folder:
            return
        html_path, json_path = write_reports(self.report, folder)
        self.status.set(f"Relatórios gravados em {folder}")
        if messagebox.askyesno("Relatórios gerados", f"Arquivos criados:\n{html_path.name}\n{json_path.name}\n\nAbrir o relatório HTML?"):
            os.startfile(html_path)  # type: ignore[attr-defined]


def run_gui() -> None:
    AnalyzerApp().mainloop()
