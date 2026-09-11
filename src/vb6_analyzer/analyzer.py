from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

from .artifacts import classify_strings, extract_strings, infer_capabilities, redact_secrets
from .models import AnalysisReport
from .pe import PEFormatError, PEParser


ANALYZER_VERSION = "0.1.0"
MAX_FILE_SIZE = 512 * 1024 * 1024


def _detect_vb(import_names: set[str], strings: list[str]) -> tuple[str, str, str, str, list[str]]:
    warnings: list[str] = []
    lowered = {name.casefold() for name in import_names}
    combined = "\n".join(strings[:50_000]).casefold()

    if "msvbvm60.dll" in lowered or "msvbvm60.dll" in combined:
        vb_version, vb_confidence = "Visual Basic 6", "alta"
    elif "msvbvm50.dll" in lowered or "msvbvm50.dll" in combined:
        vb_version, vb_confidence = "Visual Basic 5", "alta"
    elif "vb5!" in combined:
        vb_version, vb_confidence = "Visual Basic clássico (5/6)", "média"
    else:
        vb_version, vb_confidence = "Não confirmado", "baixa"
        warnings.append("O runtime do VB clássico não foi identificado; o arquivo pode não ser VB6 ou pode estar protegido/compactado.")

    # This is deliberately conservative. Both native and P-Code VB6 executables
    # rely on runtime entry points; exact mode requires parsing internal VB headers.
    if "msvbvm60.dll" in lowered or "msvbvm50.dll" in lowered:
        mode, mode_confidence = "Ainda não determinado (Native Code ou P-Code)", "baixa"
        warnings.append("O modo de compilação VB6 é uma inferência pendente neste MVP; não confunda com a arquitetura x86 do PE.")
    else:
        mode, mode_confidence = "Não aplicável/indeterminado", "baixa"
    return vb_version, vb_confidence, mode, mode_confidence, warnings


def analyze_file(file_path: str | Path) -> AnalysisReport:
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError("O arquivo excede o limite de segurança de 512 MB")

    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    analyzed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    strings = extract_strings(data)
    safe_strings = [redact_secrets(item) for item in strings]

    try:
        pe = PEParser(data).parse()
        is_pe = True
        architecture = pe.architecture
        subsystem = pe.subsystem
        entry_point = f"0x{pe.entry_point:08X}"
        image_base = f"0x{pe.image_base:X}"
        timestamp = pe.timestamp_utc
        sections = pe.sections
        imports = pe.imports
        parse_warnings: list[str] = []
    except PEFormatError as exc:
        is_pe = False
        architecture = "Desconhecida"
        subsystem = "Desconhecido"
        entry_point = "N/D"
        image_base = "N/D"
        timestamp = None
        sections = []
        imports = []
        parse_warnings = [str(exc)]

    import_names = {item.name for item in imports}
    vb_version, vb_confidence, compilation_mode, compilation_confidence, vb_warnings = _detect_vb(
        import_names, safe_strings
    )
    findings = classify_strings(safe_strings)
    capabilities = infer_capabilities(imports, findings)

    return AnalysisReport(
        schema_version="1.0",
        analyzer_version=ANALYZER_VERSION,
        file_name=path.name,
        file_path=str(path),
        file_size=size,
        sha256=sha256,
        analyzed_at_utc=analyzed_at,
        is_pe=is_pe,
        architecture=architecture,
        subsystem=subsystem,
        entry_point=entry_point,
        image_base=image_base,
        compile_timestamp_utc=timestamp,
        vb_version=vb_version,
        vb_confidence=vb_confidence,
        compilation_mode=compilation_mode,
        compilation_confidence=compilation_confidence,
        sections=sections,
        imports=imports,
        findings=findings,
        capabilities=capabilities,
        strings=safe_strings,
        warnings=parse_warnings + vb_warnings,
    )
