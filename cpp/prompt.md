You are an expert reverse-engineering engineer and IDA Pro SDK developer.

Create a complete **IDA Pro processor module** in **C++** for the target CPU architecture described by the datasheets and ISA/reference manuals I provide.

The result must be structured like a real IDA processor module, similar in completeness and organization to mature modules such as M-CORE-style layouts, and must be suitable as a serious starting point for compiling against the IDA SDK.

## Goal

Implement a new IDA processor backend for the provided architecture so that IDA can:

* recognize the processor module
* decode instructions
* format disassembly
* emulate instruction effects for cross-references and control flow
* define registers
* expose instruction metadata
* support the architecture cleanly and maintainably

This is not a toy parser. Build a real processor module skeleton with as much functional decoding and analysis support as the provided documentation reasonably allows.

## Inputs

You will be given one or more of the following:

* architecture reference manual
* ISA manual
* programmer’s manual
* core datasheet
* opcode tables
* register descriptions
* memory map details
* ABI / calling convention notes
* binary samples or test binaries

Use the provided documentation as the primary source of truth.

If the documentation is incomplete or ambiguous:

* state the ambiguity clearly
* make the most conservative reasonable implementation choice
* leave a clearly marked TODO with the exact missing detail
* do not invent undocumented behavior unless necessary for a compilable stub

## Required output

Produce a full project layout for an IDA processor module, including at minimum:

* `README.md`
* `CMakeLists.txt` or build notes
* `proc.cpp` or main module registration file
* `ana.cpp`
* `emu.cpp`
* `out.cpp`
* `ins.cpp`
* `reg.cpp`
* shared headers (for example `ins.hpp`, `regs.hpp`, `common.hpp`, etc.)
* optional helper files if needed

If a different file split is more appropriate for the target architecture, that is allowed, but keep the structure close to standard IDA processor module conventions.

## Implementation requirements

### General

* Use modern but practical C++
* Target the standard IDA processor module style used by public SDK examples
* Prefer clarity, maintainability, and correctness over over-engineering
* Keep the code close to actual IDA SDK conventions
* Avoid fake abstractions that hide the processor logic
* Add comments where they help explain architecture-specific logic
* Make the code look like something a reverse engineer would realistically maintain

### Processor module coverage

Implement the following areas as completely as possible from the docs:

1. **Processor definition**

   * processor name
   * short names
   * long names
   * assembler description
   * feature flags
   * supported endian modes if applicable
   * code/data bitness as appropriate

2. **Register model**

   * all GPRs
   * PC
   * SP if applicable
   * status/flag registers
   * special registers that matter for decoding/output
   * register enums and register name table

3. **Instruction model**

   * instruction enum list
   * canonical mnemonic table
   * instruction feature flags
   * operand types
   * categories such as jumps/calls/returns/loads/stores/arithmetic/system

4. **Decoder (`ana.cpp`)**

   * decode instruction words/packets from bytes
   * parse opcode fields exactly from the ISA docs
   * extract operands
   * populate `insn_t`
   * handle instruction length correctly
   * handle invalid/reserved encodings safely
   * support aliases only if clearly documented

5. **Emulation (`emu.cpp`)**

   * add code references for calls/jumps/branches
   * add data references for memory operands when possible
   * mark stop-flow correctly
   * handle fallthrough correctly
   * handle conditional/unconditional branch semantics
   * set up stack-tracking hooks if the ISA and ABI permit straightforward support
   * avoid pretending to fully emulate semantics beyond what IDA expects here

6. **Output (`out.cpp`)**

   * print mnemonics correctly
   * print operands correctly
   * handle immediate formatting
   * handle memory operand formatting
   * handle special syntax required by the ISA
   * follow the architecture’s documented assembly syntax, or document the chosen dialect if multiple exist

7. **Instruction metadata (`ins.cpp`)**

   * define `instruc_t` table
   * assign feature bits appropriately (`CF_USE*`, `CF_CHG*`, `CF_CALL`, `CF_STOP`, etc.)
   * keep this consistent with decoder/emulator behavior

8. **Registers metadata (`reg.cpp`)**

   * define register names
   * expose segment register placeholders if IDA expects them
   * define any virtual registers only when necessary and document why

### Architecture-specific behavior

If the architecture has unusual properties, support them intentionally:

* variable-length instructions
* instruction bundles / packets
* delay slots
* predication
* branch-likely semantics
* banked registers
* load/store with scaled offsets
* PC-relative addressing
* unusual immediate encodings
* flag side-effects
* compressed instruction sets
* dual encodings / extension spaces

If a feature is too large to fully implement in one pass, build a clean scaffold and leave exact TODO markers.

## Quality bar

The module must not be a shallow stub.

At minimum, it should:

* compile with reasonable adaptation to a real IDA SDK setup
* decode a meaningful subset of the ISA, ideally the core integer/control-flow subset
* produce believable disassembly
* create xrefs correctly for basic control flow
* be internally consistent across `ana`, `emu`, `out`, `ins`, and `reg`

If the architecture documentation is sufficient, aim for broad instruction coverage, not just a tiny subset.

## Important constraints

* Do not silently skip major instruction groups if they are documented
* Do not collapse many distinct instructions into generic placeholders
* Do not omit enums or tables for documented adjustable/variant behaviors when explicit definitions are possible
* Do not leave “stub” functions unless absolutely necessary
* If a function must be partial, explain exactly what is implemented and what remains

## Expected working style

1. First, analyze the provided docs and identify:

   * instruction encodings
   * instruction lengths
   * register set
   * endianness
   * addressing modes
   * control-flow instructions
   * calling convention clues

2. Then design the module layout.

3. Then implement all core files.

4. Then provide:

   * a summary of supported instructions
   * a list of assumptions
   * a list of TODOs for incomplete/ambiguous areas
   * build notes
   * suggestions for future extension (loader, type info, ABI improvements, etc.)

## Output formatting

Return:

1. A short architecture analysis section
2. A proposed file tree
3. Full source code for each file
4. Build notes
5. Assumptions and TODOs
6. A brief test plan using sample binaries

When possible, make the code immediately copy-pasteable.


the attached datasheet is at:
https://www.endrich.com/Datenbl%C3%A4tter/Aktive%20Komponenten/HT68FB540_550_560v200.pdf

you may take insparation form:
https://github.com/MotoFanRu/M-CORE_IDA-Pro/tree/master
and:
C:\Users\gadis\Documents\New_Programing\AI_IDA_Module_testing\workspace\epiphany_ida