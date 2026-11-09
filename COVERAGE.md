# metag module coverage (v0.7)

**Decode coverage: 100%** — every instruction decodes; no "bad instruction"
(verified: 0 BadData over multiple code regions with the standalone SLEIGH disassembler).

- **Full p-code semantics** (~94% of instructions): ALU (ADD/SUB/AND/OR/XOR/MUL +
  set-flags S-variants), MOV/MOVT/ADDT/ANDT/ORT/XORT, CMP/TST, MIN/MAX/ABS, NEG,
  all shifts (LSL/LSR/ASL/ASR), all conditional branches + BR, CALLR/RET/JUMP,
  SWAP, conditional ALU (ADDcc/SUBcc/MOVcc), GET/SET (standard+extended+post-inc,
  B/W/D/L), MGET/MSET, cross-unit MOV, MOV->TXRPT, NOP.
- **Decode-only placeholders** (~6%, no semantics): DSP (XSDW/XSDB, XFR, DALU
  DL*/DH*/DO*, MUL*T), FPU (major F), coprocessor (major E), OPC_9, and any
  remaining via generic per-major fallbacks. These decode to a named/placeholder
  instruction (no p-code) so analysis never halts; they appear in audio-codec
  code, not in the MMI/display paths. Add real semantics later if needed.

ABI (metag.cspec): args D1Ar1,D0Ar2,D1Ar3,D0Ar4,D1Ar5,D0Ar6 ; ret D0Re0 ;
link D1RtP ; stack A0StP (grows up) ; globals A1GbP.
