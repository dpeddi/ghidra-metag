# Find functions referencing any of the strings (substrings) in arg0 (comma-sep). @category metag
from ghidra.program.model.mem import MemoryAccessException
args=getScriptArgs(); needles=args[0].split("|")
mem=currentProgram.getMemory()
for needle in needles:
    pat=bytearray(needle,"ascii")
    addr=mem.findBytes(mem.getMinAddress(), pat, None, True, monitor)
    locs=[]
    while addr is not None and len(locs)<8:
        locs.append(addr); 
        addr=mem.findBytes(addr.add(1), pat, None, True, monitor)
    fns=set()
    for a in locs:
        for r in getReferencesTo(a):
            f=getFunctionContaining(r.getFromAddress())
            if f: fns.add((f.getEntryPoint().getOffset(), f.getName()))
    println("STR '%s' @%s refs-from-funcs: %s"%(needle, ",".join(str(a) for a in locs),
            ";".join("0x%x:%s"%(o,n) for o,n in sorted(fns))))
