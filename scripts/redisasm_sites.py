# Re-disassemble the functions containing the offsets in arg0 (hex/line), so they
# pick up the current .sla. Dedup by containing function; preserve names. @category metag
from ghidra.program.model.symbol import SourceType
args=getScriptArgs()
offs=[int(x,16) for x in open(args[0]).read().split() if x.strip()]
seen=set(); entries=[]
for o in offs:
    fn=getFunctionContaining(toAddr(o))
    if fn is None: continue
    e=fn.getEntryPoint().getOffset()
    if e in seen: continue
    seen.add(e); entries.append((e, fn.getName()))
done=0
for e,nm in entries:
    a=toAddr(e)
    fn=getFunctionAt(a)
    end = fn.getBody().getMaxAddress() if fn else a
    try:
        if fn is not None: removeFunction(fn)
        clearListing(a, end)
        disassemble(a)
        fn=createFunction(a,None)
        if fn is not None:
            done+=1
            if not nm.startswith("FUN_"):
                try: fn.setName(nm, SourceType.USER_DEFINED)
                except: pass
    except: pass
println("METAG-REDISASM functions_relifted=%d (of %d unique)" % (done, len(entries)))
