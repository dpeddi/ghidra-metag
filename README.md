# metag — Ghidra processor module (Imagination META) — v0

Gives Ghidra a disassembler + **decompiler (pseudo-C)** + auto xrefs for the
Frontier Silicon FS2026 core (Imagination META / "metag", 32-bit little-endian).

## Install (Ghidra 10.2.2)
Copy this `metag/` folder to:  `<GHIDRA_INSTALL>/Ghidra/Processors/metag/`
(already placed at C:\ghidra_10.2.2_PUBLIC\Ghidra\Processors\metag). Restart Ghidra.
Ghidra compiles `metag.slaspec` -> `metag.sla` automatically on first use.

## Load a core
File > Import > pick e.g. unpack/0286_core.bin
- Format: Raw Binary
- Language: `metag:LE:32:default`
- Base address: 0 (our disassemblies use file offsets; load base is not
  recoverable from the image — see ../CLAUDE.md). Then run Auto Analysis.

## Coverage (v0)
Implemented with verified encodings + p-code semantics:
- GP-ALU reg,reg,reg: ADD SUB AND OR XOR MUL
- GP-ALU reg,#imm16: MOV, ADD, SUB
- CMP (sets NF/ZF)
- Branches: B BEQ BNE BCS BCC BMI BPL (PC-relative, verified)
- CALLR (call, links D1RtP)
- RET (MOV/SWAP PC,D1RtP)
ABI (calling convention) is baked into metag.cspec:
  args D1Ar1,D0Ar2,D1Ar3,D0Ar4,D1Ar5,D0Ar6 ; return D0Re0 ; link D1RtP ;
  stack A0StP (grows up) ; globals A1GbP.

## Not yet implemented (next iterations) -> show as "bad"/unimpl
GET/SET loads/stores with offset & post-increment addressing, SHIFT details,
conditional ALU forms, ADDR-unit (A0/A1) arithmetic, MOVT/ADDT 16-bit-high,
SWAP/kick/cache, DSP (MAC/accumulators), FPU. Add by extending metag.slaspec
(field layouts are in binutils-2.40 opcodes/metag-dis.c). Validate against our
objdump output in unpack/disasm/.

Built/validated with the standalone Ghidra SLEIGH compiler (lifting-bits/sleigh).
