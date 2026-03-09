# AGENTS.proposed.md

## 1) Operating Protocol

### 1.1 Scope and authority
This file is the authoritative instruction set for creating and maintaining IDA processor modules in this repository and in copied future projects.

### 1.2 Per-prompt workflow
1. Before every prompt, read this file fully (or re-read changed sections if already loaded this session).
2. After completing a prompt, update this file only if a meaningful reusable insight was discovered.
3. Do not add filler updates when nothing important was learned.
4. If a new lesson is added, explicitly notify the user in the response.

### 1.3 When to add a lesson
Update `## 7) Session Lessons` only when at least one of these is true:
- A real bug was found with verified root cause and fix pattern.
- An important IDA SDK/API behavior detail was discovered.
- A valuable external source was found (official PDF, repo, documentation page).
- A high-value regression check prevented or detected a real failure.
- The fix is confirmed by user feedback or by strong objective verification (tests/logs/xrefs/output checks).

### 1.4 Lesson record format (mandatory fields)
Each lesson must include:
- Lesson ID
- Date
- Architecture / module
- Symptom
- Impact / severity
- Root cause
- Fix pattern
- Preventive code check (what to inspect in code before the bug appears)
- Verification / regression check
- Frequency hint (one-off / recurring / frequent)
- Source (URL/path if relevant)

Keep lessons practical and actionable.

### 1.5 Major guide-fix rule (AGENTS/AGENT files)
If a major error is found in guidance text (wrong rule, harmful instruction, misleading checklist):
1. Do not directly overwrite the authoritative guide.
2. Prepare the fix in a proposed file (`AGENTS.proposed.md`).
3. Ask user validation/approval first.
4. Apply to authoritative file only after user approval.

This rule does not apply to adding a new lesson entry.

---

## 2) Project Baseline

### 2.1 Primary objective
Given ISA/datasheet documentation, create a production-style IDA processor module that is:
- Structurally complete
- Internally consistent
- Faithful to documented encodings and semantics
- Suitable for real SDK compilation and iterative extension

### 2.2 Required project structure
Use this structure by default:
- `README.md`
- `CMakeLists.txt`
- `proc.cpp`
- `ana.cpp`
- `emu.cpp`
- `out.cpp`
- `ins.cpp`
- `ins.hpp`
- `reg.cpp`
- `regs.hpp`
- `<arch>.hpp` shared helpers

Recommended additions:
- `tests/` with small binary regression blobs
- `docs/` with opcode tables/manual excerpts/ambiguity notes

---

## 3) Engineering Standards

### 3.1 Decoder standards
- Decode exact documented fields and lengths.
- Reject invalid/reserved forms conservatively.
- Enforce alignment constraints early.
- Clear operands before decode and mark shown operands (`op.set_shown()`).
- Keep decoder logic format-focused (avoid giant opaque monoliths).

### 3.2 Emulator standards
- Add explicit code refs for branches and calls.
- Add fallthrough refs only when flow continues.
- Mark stop-flow instructions consistently with `CF_STOP`.
- Keep behavior consistent with `ins.cpp` feature bits.
- Prefer deterministic xref creation over implicit heuristics.

### 3.3 Output standards
- Use documented assembler syntax consistently.
- Ensure printed operand kinds match decoded operand types.
- Keep immediate/address formatting stable and predictable.
- Implement instruction auto-comments through `ev_get_autocmt` + `set_gen_cmt()` using SDK-correct callback args (`qstring *buf`, `const insn_t *insn`); do not use persistent `set_cmt()` as an auto-comment substitute.

### 3.4 Internal consistency requirements
- Enum values <-> instruction table <-> decoder assignments are aligned.
- Decoder operand types <-> emulator handling <-> output rendering are aligned.
- Special/virtual registers are documented and intentional.

---

## 4) Core Execution Checklists

### 4.0 First 30 minutes (new project quickstart)
1. Create required skeleton files (`proc/ana/emu/out/ins/reg` + shared header).
2. Make module load first:
   - `LPH` exported
   - correct SDK linkage/macros
   - visible `ev_init` build tag in IDA Output
3. Implement minimal decode subset:
   - one data-move instruction
   - one ALU instruction
   - one unconditional branch
   - one conditional branch
4. Verify decode path:
   - `decode_insn()` returns nonzero on known bytes
   - `create_insn()` succeeds at same EAs
5. Implement minimal emulation flow:
   - branch taken xref
   - conditional fallthrough xref
6. Validate both text and graph:
   - disassembly looks correct
   - `XrefsFrom` shows expected taken/fallthrough edges

### 4.1 Minimal build/runtime gate
1. Confirm module load in IDA Output using a clear `ev_init` build tag.
2. Confirm `decode_insn()` and `create_insn()` both succeed on known bytes.
3. Confirm at least one branch instruction produces correct xrefs and graph edges.

### 4.2 Debug flow when behavior is wrong
1. Verify loaded binary freshness (build tag; optional hash/timestamp compare).
2. Re-test on fresh IDB or undefine/recreate code in current IDB.
3. If `decode_insn()` succeeds but `create_insn()` fails, suspect ABI/layout first.
4. Validate CFG using both graph view and `XrefsFrom`.

### 4.3 Deliverable requirements
Always provide:
- Architecture analysis
- File tree
- Full source
- Build notes
- Assumptions
- TODOs / known gaps
- Concrete test plan

---

## 5) Source Notes

Record durable external references used repeatedly during module work:
- Official architecture manuals / PDF URLs
- Strong reference IDA modules (repo URLs)
- SDK documentation pages

(Add only high-value sources, not every transient lookup.)

---

## 6) Avoidable Mistakes

Treat these as default guardrails (override only with a clear documented reason):
- Do not rely only on `o_near.addr` for branch targets in emulation paths.
- Do not implement sign extension with unsigned-only arithmetic on `__EA64__` builds.
- Do not change decoder behavior without syncing `ins.cpp` feature bits and `emu.cpp` flow handling.
- Do not validate CFG only in graph view; always confirm with `XrefsFrom`.
- Do not debug ISA semantics before confirming the loaded module build/tag is the expected binary.

---

## 7) Session Lessons

### Lesson FL-IDA-BUILD-001
- Date: 2026-03-06
- Architecture/module: Cross-architecture (IDA processor modules)
- Symptom: Module compiles but load/runtime behavior is inconsistent or misleading.
- Impact/severity: High (wasted debugging time against wrong binary/runtime state).
- Root cause: Build/deploy/runtime mismatches (SDK version, macros, ABI, stale DLL in IDA path).
- Fix pattern: Enforce explicit load/build gates and runtime identity checks before ISA debugging.
- Preventive code check:
  - In build config, verify SDK version + runtime macros (`__IDP__`, `__NT__`, `__X64__`, `__EA64__` as applicable).
  - Verify `LPH` export and correct SDK import library linkage.
  - In `proc.cpp`, verify build tag log in `ev_init`.
  - Verify `processor_t` field order for target SDK version.
  - Verify `instruc_start`/`instruc_end` align with enum/table.
- Verification/regression check: IDA Output must show expected build tag and processor metadata; known sample must decode and create code.
- Frequency hint: Frequent.
- Source: local bring-up failures and repeated module debugging sessions.

### Lesson FL-IDA-CREATEINSN-001
- Date: 2026-03-06
- Architecture/module: Cross-architecture (IDA processor modules)
- Symptom: `decode_insn()` returns valid size, but `create_insn()` fails.
- Impact/severity: High (analysis cannot progress beyond bytes).
- Root cause: Instruction metadata/layout mismatch (often ABI or processor descriptor inconsistencies), not necessarily decoder logic.
- Fix pattern: Validate descriptor/layout assumptions before touching ISA decode rules.
- Preventive code check:
  - Verify `itype` values are within `[instruc_start, instruc_end)`.
  - Verify operands are reset before decode and shown operands are marked.
  - Verify `processor_t` initialization/order matches SDK headers.
- Verification/regression check: For a known valid opcode, both `decode_insn()` and `create_insn()` succeed at same EA.
- Frequency hint: Recurring.
- Source: repeated IDA module bring-up sessions.

### Lesson FL-XREF-TARGET-001
- Date: 2026-03-06
- Architecture/module: Cross-architecture (branch/call analysis)
- Symptom: Branch decodes correctly, but taken xref/graph edge is missing.
- Impact/severity: High (broken CFG, loops/functions misrepresented).
- Root cause: Target address representation mismatch (`o_near.addr` not always plain linear EA).
- Fix pattern: For branch/call immediate forms, compute target from opcode bits in `emu` when operand representation is inconsistent.
- Preventive code check: In `emu.cpp`, check branch handlers do not rely blindly on `o_near.addr`; ensure explicit cref creation path exists for immediate branch opcodes.
- Verification/regression check: `XrefsFrom(branch_ea)` must contain taken edge + fallthrough for conditional branches.
- Frequency hint: Recurring.
- Source: local Epiphany debugging logs and CFG validation.

### Lesson FL-MIXED-WIDTH-001
- Date: 2026-03-06
- Architecture/module: Cross-architecture (variable/mixed instruction widths)
- Symptom: Valid long instructions are split or decoded incorrectly, especially after edits/reanalysis.
- Impact/severity: High (wrong disassembly and cascading CFG errors).
- Root cause: Missing alignment/boundary guards and stale analysis state interactions.
- Fix pattern: Enforce architectural alignment in `ana` and validate decode boundaries on raw bytes.
- Preventive code check:
  - Ensure early alignment reject for impossible addresses.
  - Ensure per-format decode ordering prevents accidental short-form capture over valid long forms.
  - Ensure regression blob includes adjacent short/long boundary cases.
- Verification/regression check: Known mixed-width sample decodes identically in fresh IDB and after undefine/recreate cycle.
- Frequency hint: Recurring.
- Source: prior mixed-width ISA module debugging patterns.

### Lesson FL-EA64-SIGNEXT-001
- Date: 2026-03-06
- Architecture/module: Cross-architecture (`__EA64__` targets)
- Symptom: Backward branch targets become huge positive addresses.
- Impact/severity: Critical (wrong xrefs, wrong control flow, unusable analysis).
- Root cause: Sign extension performed with unsigned intermediate arithmetic.
- Fix pattern: Implement sign extension via fixed signed width (`int32`/`int64`) before widening to `sval_t`.
- Preventive code check: In shared helpers (`<arch>.hpp`), audit sign-extension function for unsigned-only math patterns; verify edge handling for field widths.
- Verification/regression check: Run backward-branch regression case; confirm taken edge resolves to negative displacement target (not high-bit polluted address).
- Frequency hint: Recurring.
- Source: local Epiphany logs (`0x28000000A` symptom) and regression script.

### Lesson SL-2026-03-06-001
- Date: 2026-03-06
- Architecture/module: Epiphany processor module
- Symptom: Conditional branch decoded correctly but graph/xrefs missed taken edge.
- Impact/severity: High (incorrect CFG and loop analysis).
- Root cause: EA64 sign-extension helper used unsigned arithmetic, turning negative displacement into huge positive value.
- Fix pattern: Sign-extend in fixed signed width before widening to `sval_t`; validate with backward branch sample.
- Preventive code check: Inspect `epy_signext()` (or equivalent) for unsigned-only operations and absence of explicit signed cast.
- Verification/regression check: `XrefsFrom(branch_ea)` includes both taken and fallthrough edges; log shows correct backward target.
- Frequency hint: Recurring class in EA64 ports.
- Source: local module debug logs and regression script.

### Lesson FL-IDA-SDK-FLAGS-001
- Date: 2026-03-09
- Architecture/module: Cross-architecture (IDA 9 SDK processor modules)
- Symptom: Build fails in `proc.cpp` with `PR_USE16`/`PR_DEFSEG16` undefined, followed by many `processor_t` initializer type-conversion errors.
- Impact/severity: High (module does not compile; misleading cascade obscures root cause).
- Root cause: This SDK branch does not define 16-bit flag macros (`PR_USE16`, `PR_DEFSEG16`); 16-bit mode is represented by not setting `PR_USE32/PR_USE64` and not setting `PR_DEFSEG32/PR_DEFSEG64`.
- Fix pattern: Use only valid `PR_*` flags for this SDK (`PRN_HEX | PR_WORD_INS | PR_RNAMESOK` for simple 16-bit targets), keep `processor_t` initializer order unchanged, then rebuild to confirm cascade disappears.
- Preventive code check:
  - In `idp.hpp`, verify available `PR_*` macros before writing module flags.
  - Confirm `processor_t` field order against the exact SDK headers used by the build.
  - Avoid copying flag sets from older/newer SDK examples without header verification.
- Verification/regression check: `cmake --build ... --config Release` must produce the target DLL with no compile errors (warnings from SDK headers may remain).
- Frequency hint: Recurring when porting modules across IDA SDK versions.
- Source: local HT68FB module bring-up against `C:\Users\gadis\Documents\New_Programing\third_party\ida-sdk\src`.

### Lesson FL-IDA-DATA-MAP-001
- Date: 2026-03-09
- Architecture/module: HT68FB / HT8-like Harvard MCUs
- Symptom: Direct-memory operands (`[m]`) render as code labels such as `loc_4`, and data refs point into ROM graph nodes.
- Impact/severity: High (misleading disassembly semantics and mixed code/data xrefs).
- Root cause: Decoder mapped `o_mem.addr` directly into current code segment linear space for raw binaries with only ROM segment.
- Fix pattern: Map direct memory to a dedicated RAM window (`HT68_RAM_BASE + m`) and ensure a RAM segment exists on file load.
- Preventive code check:
  - In shared helpers, verify `o_mem` address mapping does not use code segment base for Harvard cores.
  - In `ev_newfile`/`ev_oldfile`, ensure synthetic RAM segment is created when loader does not define one.
  - Check output examples for `[m]` accidentally resolving to `loc_*` symbols.
- Verification/regression check: In IDA, `[m]` operands should resolve to RAM symbols (`RAM:` / `byte_...`), and code graph should no longer include direct-memory labels as basic blocks.
- Frequency hint: Recurring for bare-binary bring-up without architecture-specific loaders.
- Source: local HT68FB graph/output validation screenshot and rebuild test.

### Lesson FL-IDA-AUTOCMT-001
- Date: 2026-03-09
- Architecture/module: Cross-architecture (IDA 9 procmod auto-comments)
- Symptom: Auto-comments either do not show at all, or remain visible even when UI auto-comments are disabled.
- Impact/severity: Medium-High (reduced readability or noisy listings that ignore analyst preferences).
- Root cause: Two combined mistakes:
  1) `ev_get_autocmt` handler used wrong vararg signature/return semantics.
  2) Fallback wrote persistent comments using `set_cmt()`, bypassing dynamic auto-comment policy.
- Fix pattern: Implement `ev_get_autocmt` with exact SDK signature (`qstring *buf`, `const insn_t *insn`) and status return (`1/0`), and keep comment generation dynamic via `set_gen_cmt()` only (no `set_cmt()` fallback).
- Preventive code check:
  - In emulator, reject writing persistent comments for auto-comment purposes.
-  In `proc.cpp`, verify each event handler matches exact documented argument list in `idp.hpp`.
-  For `ev_get_autocmt`, confirm return semantics are status code and buffer write, not pointer return.
-  Validate behavior with auto-comments toggled ON/OFF in the same IDB.
- Verification/regression check: With same IDB and module, comments appear when auto-comments are enabled and disappear when disabled.
- Frequency hint: Recurring.
- Source: local HT68FB bring-up/user validation + rebuild tests.
