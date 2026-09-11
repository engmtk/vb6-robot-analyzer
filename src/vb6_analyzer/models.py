from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(slots=True)
class ImportedLibrary:
    name: str
    functions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    category: str
    value: str
    confidence: str = "alta"
    evidence: str = ""


@dataclass(slots=True)
class AnalysisReport:
    schema_version: str
    analyzer_version: str
    file_name: str
    file_path: str
    file_size: int
    sha256: str
    analyzed_at_utc: str
    is_pe: bool
    architecture: str
    subsystem: str
    entry_point: str
    image_base: str
    compile_timestamp_utc: str | None
    vb_version: str
    vb_confidence: str
    compilation_mode: str
    compilation_confidence: str
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportedLibrary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[Finding] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
