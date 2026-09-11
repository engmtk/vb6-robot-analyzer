from __future__ import annotations

import re

from .models import Finding, ImportedLibrary


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.I)
UNC_RE = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\r\n\"'<>|*?]+")
PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\r\n\"'<>|*?]+")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\r\n]+", re.I)
PROGID_RE = re.compile(
    r"\b(?:ADODB|DAO|Scripting|WScript|Shell|Excel|Word|Outlook|MSXML2|WinHttp|InternetExplorer)\.[A-Za-z][A-Za-z0-9_.]+",
    re.I,
)
SQL_KEYWORD_RE = re.compile(
    r"\b(?:SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+[\[\]\w.]+\s+SET|DELETE\s+FROM|EXEC(?:UTE)?\s+|CREATE\s+(?:TABLE|PROCEDURE)|ALTER\s+(?:TABLE|PROCEDURE))",
    re.I,
)
TABLE_RE = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([\[\]A-Za-z0-9_.$#]+)", re.I)
PROC_RE = re.compile(r"\bEXEC(?:UTE)?\s+([\[\]A-Za-z0-9_.$#]+)", re.I)
SECRET_RE = re.compile(r"(?i)\b(password|pwd|senha|token|api[_ -]?key)\s*=\s*([^;\s]+)")


def extract_strings(data: bytes, minimum: int = 4, maximum_count: int = 50_000) -> list[str]:
    ascii_re = ASCII_RE if minimum == 4 else re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    utf16_re = UTF16_RE if minimum == 4 else re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)
    found: set[str] = set()
    for match in ascii_re.finditer(data):
        found.add(match.group().decode("ascii", errors="replace").strip())
        if len(found) >= maximum_count:
            break
    if len(found) < maximum_count:
        for match in utf16_re.finditer(data):
            found.add(match.group().decode("utf-16le", errors="replace").strip())
            if len(found) >= maximum_count:
                break
    return sorted((s for s in found if len(s) >= minimum), key=lambda value: value.casefold())


def redact_secrets(value: str) -> str:
    return SECRET_RE.sub(lambda m: f"{m.group(1)}=***MASCARADO***", value)


def classify_strings(strings: list[str]) -> list[Finding]:
    findings: dict[tuple[str, str], Finding] = {}

    def add(category: str, value: str, confidence: str = "alta", evidence: str = "string embutida") -> None:
        clean = redact_secrets(value.strip().rstrip(".,;"))
        if clean and len(clean) <= 1000:
            findings[(category, clean.casefold())] = Finding(category, clean, confidence, evidence)

    for original in strings:
        text = redact_secrets(original)
        for match in URL_RE.findall(text):
            add("URL", match)
        for match in UNC_RE.findall(text):
            add("Caminho UNC", match)
        for match in PATH_RE.findall(text):
            add("Caminho local", match)
        for match in REGISTRY_RE.findall(text):
            add("Registro do Windows", match)
        for match in PROGID_RE.findall(text):
            add("Componente COM/ProgID", match)

        if SQL_KEYWORD_RE.search(text) and len(text) <= 1000:
            add("Comando SQL", text, "média")
            for table in TABLE_RE.findall(text):
                add("Tabela candidata", table, "média", "identificada em comando SQL")
            for proc in PROC_RE.findall(text):
                add("Procedure candidata", proc, "média", "identificada em comando SQL")

    return sorted(findings.values(), key=lambda item: (item.category, item.value.casefold()))


def infer_capabilities(imports: list[ImportedLibrary], findings: list[Finding]) -> list[Finding]:
    libraries = {item.name.casefold() for item in imports}
    functions = {name.casefold() for item in imports for name in item.functions}
    categories = {item.category for item in findings}
    values = " ".join(item.value.casefold() for item in findings)
    result: dict[str, Finding] = {}

    def add(value: str, confidence: str, evidence: str) -> None:
        result[value] = Finding("Capacidade inferida", value, confidence, evidence)

    if {"Comando SQL", "Tabela candidata", "Procedure candidata"} & categories or any(
        token in values for token in ("adodb.", "provider=", "data source=")
    ):
        add("Acesso a banco de dados", "alta", "SQL, ADO ou string de conexão")
    if {"Caminho local", "Caminho UNC"} & categories or "scripting.filesystemobject" in values:
        add("Leitura ou gravação de arquivos", "alta", "caminhos ou FileSystemObject")
    if "URL" in categories or libraries & {"wininet.dll", "winhttp.dll", "ws2_32.dll"}:
        add("Comunicação de rede/API", "alta", "URL ou biblioteca de rede")
    if libraries & {"advapi32.dll"} and any("reg" in f for f in functions):
        add("Acesso ao Registro do Windows", "média", "funções de registro importadas")
    if "Componente COM/ProgID" in categories:
        add("Automação COM/ActiveX", "alta", "ProgID encontrado")
    if libraries & {"user32.dll", "comctl32.dll", "comdlg32.dll"}:
        add("Interface gráfica ou interação com desktop", "média", "bibliotecas de UI")
    if libraries & {"shell32.dll"} or "wscript.shell" in values:
        add("Execução ou automação de processos", "média", "Shell do Windows")
    return list(result.values())
