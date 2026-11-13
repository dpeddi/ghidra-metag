# SLEIGH semantic completion — status

## DONE (validated against objdump + lifted on inflate, 0 placeholders)
- **Gap 1 — conditional 8-bit-immediate ALU**: ADD/SUB/AND/OR/XOR #imm8 in all
  three forms (ca=1 cross-unit unconditional; ca=0 cc=A unconditional; ca=0
  conditional/predicated via ALUcc). 28,484 such words in 0286_core were
  previously op1/op2 placeholders.
- **Gap 2 — conditional MOV PC,D1RtP (conditional RET)**: `RET <cc>` emits a
  predicated return. 607 such words were previously raw `??` bytes that broke
  control flow.
- **Fix — imm16 ALU/CMP source register**: ADD/SUB/CMP #imm16 use dest_no
  (bits19-23) as the source, not bits14-18 (metag: src == dest for imm16).
  Verified `CMP D0FrT,#0x9` now matches objdump.

Fields added: imm8=(6,13) ca5=(5,5) dnu=(1,4) reth=(5,23). Subtables: DdstX
(cross-unit dest by dnu), ALUcc (condition boolean over ZF/CF/NF/VF).

## REMAINING (not flow-breaking)
- Conditional cross-unit MOV (`MOVLS Dd,Ds`, op=0xa minor=3 with cc) still
  decodes as plain `MOV` (loses the predicate; still produces a MOV so the
  decompiler doesn't break — just drops the condition).
- DSP/FPU long tail (unchanged placeholders), not used by the control code.

## Rebuild / reload in Ghidra
Ghidra recompiles metag.slaspec -> metag.sla by timestamp. After replacing the
.slaspec: delete data/languages/metag.sla (if present) to force a recompile,
reopen the program, then re-disassemble the affected code (clear+disassemble, or
Analysis > re-run) so the listing picks up the new constructors. The decompiler
then shows inflate with its error strings inline instead of "bad instruction data".

## DONE (b1 batch — validated on 0x013E7C / 0x0B2410)
- **SWAP PC,D1RtP (misc24=0x200aa0) was modelled as RET** — it is actually an
  INDIRECT CALL (jump to D1RtP, save return in D1RtP). Fixed to a computed call
  (`:CALLRtp ... { local t=D1RtP; D1RtP=inst_next; call [t]; }`). **2,471 sites**
  in 0286_core. Before: the decompiler saw a false return and dropped all code
  after it ("unreachable block"); after: the call shows as `(**(code**)(..))()`
  and flow is recovered.
- **GETL/SETL were 32-bit single-register** — they are 64-bit PAIR ops
  (`SETL [..],D0.n,D1.n`). Added gu=1 pair constructors that read/write BOTH
  D0.n (low, ea) and D1.n (high, ea+4); the generic single-reg form stays as the
  fallback for the rare A-unit pairs. No regression on normal functions.

## REMAINING (hard)
- **MSETL/MGETL** still only adjust Base (no register transfer). They save/restore
  a register SET selected by `rmask` (a decode-time constant); SLEIGH can't loop a
  runtime mask, so the prologue/epilogue callee-saved save/restore stay invisible.
  This is a main source of the remaining `in_D0_5/in_D1_5` phantom inputs. Options:
  a pcodeop, or one constructor per common rmask value.
- Function-boundary noise: some phantom-input cases (e.g. 0x013E7C) are also a
  *fragmentation* artefact — the true entry (with the MSETL save) is earlier, so
  the register looks like an input to the mid-function block.

## To apply the b1 fixes across the project
The .sla is recompiled, but existing instructions keep their OLD pcode. Re-run
disassembly on the affected code (clear+disassemble, or a full re-analysis) so the
2,471 SWAP sites and the GETL/SETL pairs pick up the new constructors.

## MSETL/MGETL — investigated, NOT modelled (too risky to rush)
Collected the full rmask->register-set mapping across 0286 (see
`MSETL_rmask_map.txt`). The encoding is **not a plain bitmask**: the saved set
depends on rmask AND a start/base register, non-linearly (e.g. A0StP rmask=0x01 ->
{D0FrT,D0.5} but rmask=0x08 -> {D0Re0,D0FrT}), and differs by base register and
unit. Modelling it wrong would corrupt analysis across thousands of prologues, so
it needs the real metag register-list decode algorithm (from the ISA manual)
before writing per-rmask constructors. Deferred. This is the main remaining source
of `in_D0_5/in_D1_5` phantom inputs in true-entry functions.
