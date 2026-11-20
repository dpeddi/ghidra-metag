# Find functions referencing a given source-file string. arg0 = substring (e.g. fs_rsa.c)
# @category metag
from ghidra.program.model.symbol import SymbolType
args=getScriptArgs(); needle=args[0]
mem=currentProgram.getMemory()
# find the string bytes in memory
found=[]
it=currentProgram.getListing().getDefinedData(True)
# brute: scan bytes for needle
target=needle.encode('ascii') if hasattr(needle,'encode') else needle
# use FindBytes via memory search
addr=mem.findBytes(mem.getMinAddress(), bytearray(needle), None, True, monitor)
while addr is not None:
    found.append(addr)
    nxt=addr.add(1)
    addr=mem.findBytes(nxt, bytearray(needle), None, True, monitor)
println("string '%s' found at: %s"%(needle, ",".join(str(a) for a in found)))
refset=set()
for a in found:
    refs=getReferencesTo(a)
    for r in refs:
        f=getFunctionContaining(r.getFromAddress())
        if f: refset.add(f.getEntryPoint().getOffset())
println("FILEFUNCS referencing functions: %d"%len(refset))
for o in sorted(refset):
    f=getFunctionAt(toAddr(o))
    println("  0x%06x %s size=%d"%(o, f.getName(), f.getBody().getNumAddresses()))
