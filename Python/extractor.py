"""
Fallback extractor for Epiphany architecture reference data.

Usage:
    python extractor.py --pdf epiphany_arch_ref.pdf --out epiphany_extracted.json

This script is intended for the case where machine-readable opcode tables
are unavailable. It attempts to extract:
- Memory map rows (Table 6 area)
- Memory-mapped register rows (Tables 27-31 area)
- Instruction catalog mnemonics (Tables 10-16 area)
- Decode table rows from Appendix C using Camelot/Tabula when available
"""

import argparse
import json
import re
from pathlib import Path


def read_pdf_text(pdf_path: Path) -> str:
    try:
        from PyPDF2 import PdfReader
    except ImportError as exc:
        raise RuntimeError(
            "PyPDF2 is required: pip install PyPDF2"
        ) from exc

    reader = PdfReader(str(pdf_path))
    parts = []
    for page in reader.pages:
        text = page.extract_text() or ""
        parts.append(text)
    return "\n".join(parts)


def extract_memory_map(text: str):
    patterns = [
        (r"Interrupt Vector Table\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "IVT"),
        (r"Bank 0\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "Bank0"),
        (r"Bank 1\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "Bank1"),
        (r"Bank 2\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "Bank2"),
        (r"Bank 3\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "Bank3"),
        (r"Memory Mapped Registers\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)", "MMR"),
    ]

    out = []
    for pattern, name in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        out.append(
            {
                "name": name,
                "start": "0x" + m.group(1).upper(),
                "end": "0x" + m.group(2).upper(),
            }
        )
    return out


def extract_registers(text: str):
    # Matches rows like:
    # 0xF0400 CONFIG RD/WR Core configuration register
    row_re = re.compile(
        r"(0xF[0-9A-Fa-f]{4,})\s+([A-Z0-9_]+)\s+([A-Z/]+)\s+([^\n]+)"
    )

    seen = set()
    regs = []
    for m in row_re.finditer(text):
        addr, name, access, comment = m.groups()
        key = (addr.upper(), name)
        if key in seen:
            continue
        seen.add(key)
        regs.append(
            {
                "address": addr.upper(),
                "name": name,
                "access": access,
                "comment": comment.strip(),
            }
        )
    return regs


def extract_instruction_catalog(text: str):
    known = [
        "B<COND>",
        "B",
        "BL",
        "JR",
        "JALR",
        "LDR",
        "STR",
        "TESTSET",
        "ADD",
        "SUB",
        "ASR",
        "LSR",
        "LSL",
        "ORR",
        "AND",
        "EOR",
        "BITR",
        "FADD",
        "FSUB",
        "FMUL",
        "FMADD",
        "FMSUB",
        "FABS",
        "FIX",
        "FLOAT",
        "IADD",
        "ISUB",
        "IMUL",
        "IMADD",
        "IMSUB",
        "MOV",
        "MOVT",
        "MOV<COND>",
        "MOVTS",
        "MOVFS",
        "NOP",
        "IDLE",
        "RTS",
        "RTI",
        "GID",
        "GIE",
        "BKPT",
        "MBKPT",
        "TRAP",
        "SYNC",
        "WAND",
    ]
    present = []
    for item in known:
        if re.search(r"\b" + re.escape(item) + r"\b", text):
            present.append(item)
    return present


def extract_decode_rows(pdf_path: Path):
    rows = []

    # Camelot path.
    try:
        import camelot  # type: ignore

        for flavor in ("lattice", "stream"):
            tables = camelot.read_pdf(
                str(pdf_path),
                pages="154-155",
                flavor=flavor,
            )
            for table in tables:
                data = table.df.values.tolist()
                for row in data:
                    line = " | ".join(str(col).strip() for col in row if str(col).strip())
                    if not line:
                        continue
                    rows.append({"source": "camelot:" + flavor, "raw": line})
    except Exception:
        pass

    # Tabula path.
    try:
        import tabula  # type: ignore

        dfs = tabula.read_pdf(
            str(pdf_path),
            pages="154-155",
            lattice=True,
            multiple_tables=True,
        )
        for df in dfs:
            for _, series in df.iterrows():
                row = [str(x).strip() for x in series.tolist() if str(x).strip() != "nan"]
                if not row:
                    continue
                rows.append({"source": "tabula", "raw": " | ".join(row)})
    except Exception:
        pass

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", required=True, help="Path to epiphany_arch_ref.pdf")
    parser.add_argument(
        "--out",
        default="epiphany_extracted.json",
        help="Output JSON file",
    )
    args = parser.parse_args()

    pdf_path = Path(args.pdf)
    if not pdf_path.exists():
        raise SystemExit("PDF not found: {}".format(pdf_path))

    text = read_pdf_text(pdf_path)
    out = {
        "source": "Epiphany Architecture Reference Manual (REV 14.03.11)",
        "memory_map": extract_memory_map(text),
        "registers": extract_registers(text),
        "instruction_catalog": extract_instruction_catalog(text),
        "decode_rows_raw": extract_decode_rows(pdf_path),
        "notes": [
            "Decode rows are emitted raw and require manual validation.",
            "If decode_rows_raw is empty, table extraction failed.",
        ],
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("Wrote {}".format(out_path))


if __name__ == "__main__":
    main()

