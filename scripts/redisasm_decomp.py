# Clear, re-disassemble and decompile the function(s) at arg0 (comma hex). @category metag
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
args=getScriptArgs(); offs=[x for x in args[0].split(",") if x]
for h in offs:
    a=toAddr(int(h,16))
    fn=getFunctionContaining(a)
    end = fn.getBody().getMaxAddress() if fn else a.add(0x400)
    start = fn.getEntryPoint() if fn else a
    if fn: removeFunction(fn)
    clearListing(start, end)
    disassemble(start)
    createFunction(start, None)
di=DecompInterface(); di.openProgram(currentProgram); mon=ConsoleTaskMonitor()
for h in offs:
    fn=getFunctionContaining(toAddr(int(h,16)))
    if fn is None: println("NO-FUNC %s"%h); continue
    r=di.decompileFunction(fn,60,mon)
    println("=====BEGIN %s %s====="%(h,fn.getName()))
    if r and r.decompiledFunction: println(r.decompiledFunction.getC())
    else: println("DECOMP-FAIL")
    println("=====END %s====="%h)
di.dispose()
