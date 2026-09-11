from __future__ import annotations

import datetime as dt
import struct
from dataclasses import dataclass

from .models import ImportedLibrary, Section


class PEFormatError(ValueError):
    pass


MACHINES = {
    0x014C: "x86 (32 bits)",
    0x8664: "x64 (64 bits)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    9: "Windows CE GUI",
}


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PEFormatError("Leitura fora dos limites do arquivo")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PEFormatError("Leitura fora dos limites do arquivo")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise PEFormatError("Leitura fora dos limites do arquivo")
    return struct.unpack_from("<Q", data, offset)[0]


def _cstring(data: bytes, offset: int, limit: int = 1024) -> str:
    if not 0 <= offset < len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", errors="replace")


@dataclass(slots=True)
class PEInfo:
    architecture: str
    subsystem: str
    entry_point: int
    image_base: int
    timestamp_utc: str | None
    sections: list[Section]
    imports: list[ImportedLibrary]
    is_64_bit: bool


class PEParser:
    """Small, defensive PE32/PE32+ parser focused on import discovery."""

    def __init__(self, data: bytes):
        self.data = data
        self.sections: list[Section] = []

    def parse(self) -> PEInfo:
        data = self.data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEFormatError("O arquivo não possui cabeçalho DOS/PE válido")

        pe_offset = _u32(data, 0x3C)
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEFormatError("Assinatura PE não encontrada")

        coff = pe_offset + 4
        machine = _u16(data, coff)
        section_count = _u16(data, coff + 2)
        timestamp = _u32(data, coff + 4)
        optional_size = _u16(data, coff + 16)
        optional = coff + 20
        if optional + optional_size > len(data):
            raise PEFormatError("Cabeçalho opcional PE truncado")

        magic = _u16(data, optional)
        if magic == 0x10B:
            is_64 = False
            image_base = _u32(data, optional + 28)
            data_directory = optional + 96
        elif magic == 0x20B:
            is_64 = True
            image_base = _u64(data, optional + 24)
            data_directory = optional + 112
        else:
            raise PEFormatError(f"Formato PE opcional desconhecido: 0x{magic:04X}")

        entry_point = _u32(data, optional + 16)
        subsystem = _u16(data, optional + 68)
        section_table = optional + optional_size
        if section_count > 96 or section_table + section_count * 40 > len(data):
            raise PEFormatError("Tabela de seções inválida ou truncada")

        for index in range(section_count):
            pos = section_table + index * 40
            name = data[pos : pos + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            self.sections.append(
                Section(
                    name=name or f"section_{index}",
                    virtual_size=_u32(data, pos + 8),
                    virtual_address=_u32(data, pos + 12),
                    raw_size=_u32(data, pos + 16),
                    raw_offset=_u32(data, pos + 20),
                    characteristics=_u32(data, pos + 36),
                )
            )

        imports: list[ImportedLibrary] = []
        # Import directory is data-directory entry 1 (RVA + size).
        if data_directory + 16 <= optional + optional_size:
            import_rva = _u32(data, data_directory + 8)
            import_size = _u32(data, data_directory + 12)
            if import_rva and import_size:
                imports = self._parse_imports(import_rva, import_size, is_64)

        timestamp_text = None
        if timestamp:
            try:
                timestamp_text = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                timestamp_text = None

        return PEInfo(
            architecture=MACHINES.get(machine, f"Máquina 0x{machine:04X}"),
            subsystem=SUBSYSTEMS.get(subsystem, f"Subsistema {subsystem}"),
            entry_point=entry_point,
            image_base=image_base,
            timestamp_utc=timestamp_text,
            sections=self.sections,
            imports=imports,
            is_64_bit=is_64,
        )

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    return None
                offset = section.raw_offset + delta
                return offset if 0 <= offset < len(self.data) else None
        # Some directories can point into headers.
        return rva if 0 <= rva < len(self.data) else None

    def _parse_imports(self, rva: int, size: int, is_64: bool) -> list[ImportedLibrary]:
        start = self.rva_to_offset(rva)
        if start is None:
            return []
        imports: list[ImportedLibrary] = []
        max_descriptors = min(4096, max(1, size // 20 + 1))
        for index in range(max_descriptors):
            pos = start + index * 20
            if pos + 20 > len(self.data):
                break
            original_thunk, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, pos)
            if not any((original_thunk, stamp, chain, name_rva, first_thunk)):
                break
            name_pos = self.rva_to_offset(name_rva)
            if name_pos is None:
                continue
            library_name = _cstring(self.data, name_pos)
            thunk_rva = original_thunk or first_thunk
            functions = self._parse_thunks(thunk_rva, is_64)
            imports.append(ImportedLibrary(name=library_name, functions=functions))
        return imports

    def _parse_thunks(self, thunk_rva: int, is_64: bool) -> list[str]:
        offset = self.rva_to_offset(thunk_rva)
        if offset is None:
            return []
        functions: list[str] = []
        width = 8 if is_64 else 4
        ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000
        for index in range(8192):
            pos = offset + index * width
            if pos + width > len(self.data):
                break
            value = _u64(self.data, pos) if is_64 else _u32(self.data, pos)
            if value == 0:
                break
            if value & ordinal_mask:
                functions.append(f"ordinal:{value & 0xFFFF}")
                continue
            hint_name = self.rva_to_offset(value)
            if hint_name is None or hint_name + 2 >= len(self.data):
                continue
            name = _cstring(self.data, hint_name + 2)
            if name:
                functions.append(name)
        return functions
