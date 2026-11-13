# Headless: merge mis-seeded fragments into their parent function.
# arg0 = file of fragment offsets (hex, one per line). For each, the preceding
# function falls through into it, so we delete the fragment and recreate the
# parent (preserving its name) to re-flow the body over the merged region.
# @category metag
from ghidra.program.model.symbol import SourceType
args = getScriptArgs()
frags = [int(x,16) for x in open(args[0]).read().split() if x.strip()]
fm = currentProgram.getFunctionManager()
parents = {}   # parent_entry_offset -> name
deleted = 0
# 1) record parents (function containing fragment-1) BEFORE deleting
for f in frags:
    pf = getFunctionContaining(toAddr(f-1))
    if pf is not None:
        parents[pf.getEntryPoint().getOffset()] = pf.getName()
# 2) delete fragment functions
for f in frags:
    fn = getFunctionAt(toAddr(f))
    if fn is not None:
        try: removeFunction(fn); deleted += 1
        except: pass
# 3) recreate parents so their bodies re-flow over the removed fragments
recreated = 0
for off,nm in parents.items():
    a = toAddr(off)
    fn = getFunctionAt(a)
    try:
        if fn is not None: removeFunction(fn)
        fn = createFunction(a, None)
        if fn is not None:
            recreated += 1
            if not nm.startswith("FUN_"):
                try: fn.setName(nm, SourceType.USER_DEFINED)
                except: pass
    except: pass
println("METAG-MERGE deleted=%d parents_recreated=%d (of %d parents)" % (deleted, recreated, len(parents)))
