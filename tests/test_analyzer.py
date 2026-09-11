from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vb6_analyzer.analyzer import analyze_file
from vb6_analyzer.artifacts import classify_strings, redact_secrets
from vb6_analyzer.pe import PEFormatError, PEParser
from vb6_analyzer.report import write_reports


def build_test_pe() -> bytes:
    """Create a tiny PE32-shaped fixture with one VB6 import; it is not executed."""
    data = bytearray(0x700)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 1_700_000_000, 0, 0, 0xE0, 0x0102)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1100)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 8, 0x1000, 40)

    section = optional + 0xE0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIIIIIHHI", data, section + 8, 0x500, 0x1000, 0x500, 0x200, 0, 0, 0, 0, 0x40000040)

    # IMAGE_IMPORT_DESCRIPTOR and terminator.
    struct.pack_into("<IIIII", data, 0x200, 0x1040, 0, 0, 0x1030, 0x1040)
    data[0x230:0x23E] = b"MSVBVM60.DLL\0"
    struct.pack_into("<II", data, 0x240, 0x1050, 0)
    struct.pack_into("<H", data, 0x250, 0)
    data[0x252:0x25D] = b"ThunRTMain\0"
    evidence = (
        b"https://api.exemplo.local/cnpj\0"
        b"C:\\Entrada\\arquivo.txt\0"
        b"SELECT ID, NOME FROM TB_CLIENTES\0"
        b"ADODB.Connection\0"
        b"Password=segredo;User ID=robo\0"
    )
    data[0x300 : 0x300 + len(evidence)] = evidence
    return bytes(data)


class PEParserTests(unittest.TestCase):
    def test_rejects_non_pe(self) -> None:
        with self.assertRaises(PEFormatError):
            PEParser(b"not a Windows executable").parse()

    def test_reads_imports(self) -> None:
        pe = PEParser(build_test_pe()).parse()
        self.assertEqual(pe.architecture, "x86 (32 bits)")
        self.assertEqual(pe.imports[0].name, "MSVBVM60.DLL")
        self.assertIn("ThunRTMain", pe.imports[0].functions)


class ArtifactTests(unittest.TestCase):
    def test_classifies_sql_and_url(self) -> None:
        findings = classify_strings(["SELECT * FROM TB_TESTE", "https://example.test/v1"])
        categories = {item.category for item in findings}
        self.assertIn("Comando SQL", categories)
        self.assertIn("Tabela candidata", categories)
        self.assertIn("URL", categories)

    def test_redacts_password(self) -> None:
        self.assertNotIn("segredo", redact_secrets("Password=segredo;User ID=robo"))


class EndToEndTests(unittest.TestCase):
    def test_analysis_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            exe = folder / "RoboTeste.exe"
            exe.write_bytes(build_test_pe())
            report = analyze_file(exe)
            self.assertEqual(report.vb_version, "Visual Basic 6")
            self.assertTrue(any(f.value == "Acesso a banco de dados" for f in report.capabilities))
            self.assertFalse(any("segredo" in value for value in report.strings))
            html_path, json_path = write_reports(report, folder / "relatorios")
            self.assertTrue(html_path.is_file())
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["file_name"], "RoboTeste.exe")


if __name__ == "__main__":
    unittest.main()
