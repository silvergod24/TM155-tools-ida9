# Epiphany IDA 9.3 Processor Module

This package contains:
- `epiphany.py` (processor module)
- `epiphany.json` (register/memory database)
- `extractor.py` (fallback PDF table extractor for opcode decode rows)

## Install

1. Copy `epiphany.py` and `epiphany.json` to:
   - `%APPDATA%\Hex-Rays\IDA Pro\procs\`
2. Optional: copy `extractor.py` there too (or keep it elsewhere).

## Load a Binary

1. Open IDA Pro 9.3.
2. Load your Epiphany binary.
3. In the processor selector, choose `epiphany`.
4. Finish load; the module will add the MMR segment and register labels.

## Important Note About Decode Coverage

The online manual text extraction did not expose `Table 66: Epiphany Instruction Decode Table`, so opcode bitmasks were not hardcoded in `epiphany.py`.

To fill decode rules from your local PDF:
1. Install dependencies:
   - `pip install PyPDF2 camelot-py tabula-py`
2. Run:
   - `python extractor.py --pdf epiphany_arch_ref.pdf --out epiphany_extracted.json`
3. Validate extracted decode rows and convert them into IDA decode masks before enabling full analysis.

## Troubleshooting

- If output rendering fails, check IDA Output window for Python traceback.
- If registers are not named, confirm `epiphany.json` is in `%APPDATA%\Hex-Rays\IDA Pro\procs\`.
