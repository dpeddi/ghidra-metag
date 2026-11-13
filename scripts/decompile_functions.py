# Headless: decompile functions at the offsets in arg0 (comma-separated hex) to C.
# Writes each to arg1/<offset>.c and prints them. @category metag
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
args = getScriptArgs()
offs = [x for x in args[0].split(",") if x]
outdir = args[1] if len(args) > 1 else "/tmp/decomp"
try: os.makedirs(outdir)
except: pass
di = DecompInterface(); di.openProgram(currentProgram)
mon = ConsoleTaskMonitor()
for h in offs:
    a = toAddr(int(h, 16))
    fn = getFunctionContaining(a)
    if fn is None:
        println("NO-FUNC %s" % h); continue
    res = di.decompileFunction(fn, 60, mon)
    if res and res.decompiledFunction:
        c = res.decompiledFunction.getC()
        p = os.path.join(outdir, "%s.c" % h)
        open(p, "w").write(c)
        println("=====BEGIN %s %s=====" % (h, fn.getName()))
        println(c)
        println("=====END %s=====" % h)
    else:
        println("DECOMP-FAIL %s" % h)
di.dispose()
