# READ-ONLY: re-disassemble a SAMPLE of previously-bad addresses with current .sla.
# @category metag
from ghidra.app.cmd.disassemble import DisassembleCommand
bad=[int(l.split()[0],16) for l in open("/sessions/rcw-01x2jnmdnwx2yvkfqsf9a7x3/bad_instr.txt")]
sample=bad[:150]
listing=currentProgram.getListing()
ok=0; still=0; outs=[]
for off in sample:
    a=toAddr(off)
    try: listing.clearCodeUnits(a, a.add(3), False)
    except: pass
    DisassembleCommand(a, None, False).applyTo(currentProgram)
    ins=listing.getInstructionAt(a)
    s=ins.toString() if ins else None
    if ins and ins.getMnemonicString() not in (None,"??"):
        ok+=1
        if len(outs)<18: outs.append("OK  %08x %s"%(off,s))
    else:
        still+=1
        if len(outs)<18: outs.append("BAD %08x"%off)
println("sample %d: now-decoding=%d still-bad=%d"%(len(sample),ok,still))
for o in outs: println("   "+o)
