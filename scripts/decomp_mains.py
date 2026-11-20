# READ-ONLY: map rodata segs, decompile main-task candidates. @category metag
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import jarray
mem=currentProgram.getMemory(); af=currentProgram.getAddressFactory().getDefaultAddressSpace()
for name,ff,va,ln in [("a00",0xb166c,0xb012d190,0x1e96c4),("a40",0x29d4dc,0xb0319000,0x8b000),
                      ("sys",0x27e2bc-0x1bc,0x27e100+0xB0456F04,0x4000)]:
    try:
        src=jarray.zeros(ln,'b'); mem.getBytes(af.getAddress(ff),src)
        mem.createInitializedBlock("sc_"+name,af.getAddress(va),ln,(0),None,False)
        mem.setBytes(af.getAddress(va),src)
    except Exception as e: pass
fm=currentProgram.getFunctionManager(); dec=DecompInterface(); dec.openProgram(currentProgram); mon=ConsoleTaskMonitor()
for off in (0x01cd6c,0x158618,0x031018,0x0dfe38,0x026778):
    f=fm.getFunctionAt(toAddr(off))
    if not f: println("no func @%x"%off); continue
    println("\n################ FUN_%06x  (callees=%d) ################"%(off,len(f.getCalledFunctions(mon))))
    r=dec.decompileFunction(f,90,mon)
    if r and r.decompileCompleted():
        c=r.getDecompiledFunction().getC()
        println(c[:2600])
    else: println("[decompile failed]")
