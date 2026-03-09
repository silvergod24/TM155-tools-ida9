# IDA Processor Module: Holtek HT68FB540/550/560

This project is a production-style starter IDA processor module for the Holtek
HT68FB540/550/560 family (HT8 core).

## Implemented

- Processor registration and event wiring (`proc.cpp`)
- Register model for core architectural registers (`a`, `status`, `pcl`, `bp`,
  `mp0`, `mp1l`, `mp1h`, `iar0`, `iar1`, `tblp`, `tbhp`, `tblh`) plus virtual
  `pc`, `sp`, and required segment registers
- Full documented 56-instruction core decode from instruction summary:
  - arithmetic/logic (`add/addm/sub/subm/...`)
  - immediate operations (`add a,x`, `mov a,x`, `ret a,x`, ...)
  - rotate/swap/daa
  - direct memory operations (`clr/set/cpl/inc/dec`)
  - table read family (`tabrdc/tabrdl/itabrdc/itabrdl`)
  - branch/call/return (`jmp/call/ret/reti`)
  - conditional skip family (`sz/sza/snz/szb/snzb/siz/siza/sdz/sdza`)
  - bit operations (`set/clr [m].i`)
- Emulator support for:
  - direct xrefs for call/jump
  - dual-edge skip semantics (next and skip-next)
  - memory read/write drefs for `[m]` operands
  - stop-flow behavior for `jmp`, `ret`, `reti`, `ret a,x`, `halt`
- Output support for Holtek syntax:
  - `[m]` memory form
  - `[m].i` bit form
  - immediate and absolute code operands

## Build

```bash
cmake -S . -B build -DIDA_SDK_DIR=/path/to/idasdk
cmake --build build --config Release
```

Copy the built module (`ht68fb` / `ht68fb.dll`) into IDA `procs/`.

## Notes and assumptions

- Instruction width is implemented as fixed 1 word (`2` bytes in IDA memory).
- Decoder uses canonical HT8 opcode families with:
  - direct memory operand `m` decoded as 8-bit bank-0 direct address
  - absolute `call/jmp` target decoded as 13-bit word address, mapped within
    current 8K-word bank in linear IDA EA space
- Skip instructions are treated as conditional control flow that can either
  execute next instruction or skip exactly one instruction word.

## TODO / known gaps

- Confirm and refine model-specific high address behavior across:
  - HT68FB540 (4K words)
  - HT68FB550 (8K words)
  - HT68FB560 (16K words, dual-bank behavior via `BP.5`)
- Add optional processor subtypes/config to select exact code address width and
  banking policy for `call/jmp`.
- Add loader integration or `ev_creating_segm` policy for named SFR/RAM layout.
- Add stack pointer delta tracking when a calling-convention policy is chosen.
- Validate opcode map against real binaries from all three family members.

## Suggested regression checks

1. Create byte blobs containing one sample from each opcode family.
2. Confirm `decode_insn()` and `create_insn()` both succeed at same EAs.
3. Verify `XrefsFrom`:
   - `call` has call cref + fallthrough
   - `jmp` has jump cref and no fallthrough
   - skip instructions have both next and skip-next edges
4. Validate `[m].i` output formatting for `set/clr/snz/sz` bit forms.
5. Re-run after undefine/recreate in same IDB to ensure stable decode output.
