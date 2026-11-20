# READ-ONLY: re-disassemble the user's function region + a CT/MOV sample.
# @category metag
from ghidra.app.cmd.disassemble import DisassembleCommand
listing=currentProgram.getListing()
addrs=range(0x53494,0x53514,4)
for off in addrs:
    a=toAddr(off)
    try: listing.clearCodeUnits(a,a.add(3),False)
    except: pass
    DisassembleCommand(a,None,False).applyTo(currentProgram)
    ins=listing.getInstructionAt(a)
    println("%08x  %s"%(off, ins.toString() if ins else "<BAD>"))
